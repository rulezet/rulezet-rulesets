rule TTP_XOR_MULT_DOSStub_e563 {
  strings:
    $key_e563 = { b1 0b [2] c5 13 [2] 82 11 [2] c5 00 [2] 8b 0c [2] 87 06 [2] 90 0d [2] 8b 43 [2] b6 }

  condition:
    any of them
}