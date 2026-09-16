rule TTP_XOR_MULT_DOSStub_c348 {
  strings:
    $key_c348 = { 97 20 [2] e3 38 [2] a4 3a [2] e3 2b [2] ad 27 [2] a1 2d [2] b6 26 [2] ad 68 [2] 90 }

  condition:
    any of them
}