rule TTP_XOR_MULT_DOSStub_9abd {
  strings:
    $key_9abd = { ce d5 [2] ba cd [2] fd cf [2] ba de [2] f4 d2 [2] f8 d8 [2] ef d3 [2] f4 9d [2] c9 }

  condition:
    any of them
}