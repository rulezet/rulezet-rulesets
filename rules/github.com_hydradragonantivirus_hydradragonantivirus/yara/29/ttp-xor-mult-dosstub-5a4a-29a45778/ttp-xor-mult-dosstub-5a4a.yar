rule TTP_XOR_MULT_DOSStub_5a4a {
  strings:
    $key_5a4a = { 0e 22 [2] 7a 3a [2] 3d 38 [2] 7a 29 [2] 34 25 [2] 38 2f [2] 2f 24 [2] 34 6a [2] 09 }

  condition:
    any of them
}