rule TTP_XOR_MULT_DOSStub_4a7f {
  strings:
    $key_4a7f = { 1e 17 [2] 6a 0f [2] 2d 0d [2] 6a 1c [2] 24 10 [2] 28 1a [2] 3f 11 [2] 24 5f [2] 19 }

  condition:
    any of them
}