rule TTP_XOR_MULT_DOSStub_d569 {
  strings:
    $key_d569 = { 81 01 [2] f5 19 [2] b2 1b [2] f5 0a [2] bb 06 [2] b7 0c [2] a0 07 [2] bb 49 [2] 86 }

  condition:
    any of them
}