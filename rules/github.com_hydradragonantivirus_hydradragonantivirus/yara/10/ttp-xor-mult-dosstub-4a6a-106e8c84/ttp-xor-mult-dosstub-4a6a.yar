rule TTP_XOR_MULT_DOSStub_4a6a {
  strings:
    $key_4a6a = { 1e 02 [2] 6a 1a [2] 2d 18 [2] 6a 09 [2] 24 05 [2] 28 0f [2] 3f 04 [2] 24 4a [2] 19 }

  condition:
    any of them
}