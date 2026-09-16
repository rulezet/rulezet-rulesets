rule TTP_XOR_MULT_DOSStub_d529 {
  strings:
    $key_d529 = { 81 41 [2] f5 59 [2] b2 5b [2] f5 4a [2] bb 46 [2] b7 4c [2] a0 47 [2] bb 09 [2] 86 }

  condition:
    any of them
}