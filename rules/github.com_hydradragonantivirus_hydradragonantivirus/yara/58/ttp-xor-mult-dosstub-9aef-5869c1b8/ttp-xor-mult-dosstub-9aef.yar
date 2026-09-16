rule TTP_XOR_MULT_DOSStub_9aef {
  strings:
    $key_9aef = { ce 87 [2] ba 9f [2] fd 9d [2] ba 8c [2] f4 80 [2] f8 8a [2] ef 81 [2] f4 cf [2] c9 }

  condition:
    any of them
}