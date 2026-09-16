rule TTP_XOR_MULT_DOSStub_c3f8 {
  strings:
    $key_c3f8 = { 97 90 [2] e3 88 [2] a4 8a [2] e3 9b [2] ad 97 [2] a1 9d [2] b6 96 [2] ad d8 [2] 90 }

  condition:
    any of them
}