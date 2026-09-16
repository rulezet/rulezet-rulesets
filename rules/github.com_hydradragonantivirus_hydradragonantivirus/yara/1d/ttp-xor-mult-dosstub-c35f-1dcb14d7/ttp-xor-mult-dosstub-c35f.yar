rule TTP_XOR_MULT_DOSStub_c35f {
  strings:
    $key_c35f = { 97 37 [2] e3 2f [2] a4 2d [2] e3 3c [2] ad 30 [2] a1 3a [2] b6 31 [2] ad 7f [2] 90 }

  condition:
    any of them
}