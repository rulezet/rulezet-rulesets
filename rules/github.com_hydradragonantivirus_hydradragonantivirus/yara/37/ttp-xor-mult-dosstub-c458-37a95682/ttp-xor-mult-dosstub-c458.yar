rule TTP_XOR_MULT_DOSStub_c458 {
  strings:
    $key_c458 = { 90 30 [2] e4 28 [2] a3 2a [2] e4 3b [2] aa 37 [2] a6 3d [2] b1 36 [2] aa 78 [2] 97 }

  condition:
    any of them
}