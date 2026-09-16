rule TTP_XOR_MULT_DOSStub_c45f {
  strings:
    $key_c45f = { 90 37 [2] e4 2f [2] a3 2d [2] e4 3c [2] aa 30 [2] a6 3a [2] b1 31 [2] aa 7f [2] 97 }

  condition:
    any of them
}