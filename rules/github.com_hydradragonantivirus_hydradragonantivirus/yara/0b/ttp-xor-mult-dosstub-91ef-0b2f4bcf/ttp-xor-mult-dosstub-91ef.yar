rule TTP_XOR_MULT_DOSStub_91ef {
  strings:
    $key_91ef = { c5 87 [2] b1 9f [2] f6 9d [2] b1 8c [2] ff 80 [2] f3 8a [2] e4 81 [2] ff cf [2] c2 }

  condition:
    any of them
}