rule TTP_XOR_MULT_DOSStub_4a3f {
  strings:
    $key_4a3f = { 1e 57 [2] 6a 4f [2] 2d 4d [2] 6a 5c [2] 24 50 [2] 28 5a [2] 3f 51 [2] 24 1f [2] 19 }

  condition:
    any of them
}