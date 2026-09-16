rule TTP_XOR_MULT_DOSStub_5a5a {
  strings:
    $key_5a5a = { 0e 32 [2] 7a 2a [2] 3d 28 [2] 7a 39 [2] 34 35 [2] 38 3f [2] 2f 34 [2] 34 7a [2] 09 }

  condition:
    any of them
}