rule TTP_XOR_MULT_DOSStub_5a7f {
  strings:
    $key_5a7f = { 0e 17 [2] 7a 0f [2] 3d 0d [2] 7a 1c [2] 34 10 [2] 38 1a [2] 2f 11 [2] 34 5f [2] 09 }

  condition:
    any of them
}