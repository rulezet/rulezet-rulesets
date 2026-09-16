rule TTP_XOR_MULT_DOSStub_c363 {
  strings:
    $key_c363 = { 97 0b [2] e3 13 [2] a4 11 [2] e3 00 [2] ad 0c [2] a1 06 [2] b6 0d [2] ad 43 [2] 90 }

  condition:
    any of them
}