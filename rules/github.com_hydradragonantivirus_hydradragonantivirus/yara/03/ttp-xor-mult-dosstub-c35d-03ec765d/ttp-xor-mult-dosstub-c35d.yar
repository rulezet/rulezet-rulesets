rule TTP_XOR_MULT_DOSStub_c35d {
  strings:
    $key_c35d = { 97 35 [2] e3 2d [2] a4 2f [2] e3 3e [2] ad 32 [2] a1 38 [2] b6 33 [2] ad 7d [2] 90 }

  condition:
    any of them
}