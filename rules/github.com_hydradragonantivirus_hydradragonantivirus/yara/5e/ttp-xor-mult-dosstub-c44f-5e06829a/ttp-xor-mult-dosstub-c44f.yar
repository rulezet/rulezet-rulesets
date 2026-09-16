rule TTP_XOR_MULT_DOSStub_c44f {
  strings:
    $key_c44f = { 90 27 [2] e4 3f [2] a3 3d [2] e4 2c [2] aa 20 [2] a6 2a [2] b1 21 [2] aa 6f [2] 97 }

  condition:
    any of them
}