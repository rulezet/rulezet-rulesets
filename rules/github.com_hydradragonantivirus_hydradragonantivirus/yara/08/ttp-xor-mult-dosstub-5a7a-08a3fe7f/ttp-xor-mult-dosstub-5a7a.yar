rule TTP_XOR_MULT_DOSStub_5a7a {
  strings:
    $key_5a7a = { 0e 12 [2] 7a 0a [2] 3d 08 [2] 7a 19 [2] 34 15 [2] 38 1f [2] 2f 14 [2] 34 5a [2] 09 }

  condition:
    any of them
}