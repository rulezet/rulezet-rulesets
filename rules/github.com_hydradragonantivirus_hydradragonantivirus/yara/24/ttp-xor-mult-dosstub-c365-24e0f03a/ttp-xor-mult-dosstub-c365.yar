rule TTP_XOR_MULT_DOSStub_c365 {
  strings:
    $key_c365 = { 97 0d [2] e3 15 [2] a4 17 [2] e3 06 [2] ad 0a [2] a1 00 [2] b6 0b [2] ad 45 [2] 90 }

  condition:
    any of them
}