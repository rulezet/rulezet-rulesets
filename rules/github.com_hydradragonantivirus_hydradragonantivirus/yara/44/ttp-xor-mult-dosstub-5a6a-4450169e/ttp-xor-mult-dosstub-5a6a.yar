rule TTP_XOR_MULT_DOSStub_5a6a {
  strings:
    $key_5a6a = { 0e 02 [2] 7a 1a [2] 3d 18 [2] 7a 09 [2] 34 05 [2] 38 0f [2] 2f 04 [2] 34 4a [2] 09 }

  condition:
    any of them
}