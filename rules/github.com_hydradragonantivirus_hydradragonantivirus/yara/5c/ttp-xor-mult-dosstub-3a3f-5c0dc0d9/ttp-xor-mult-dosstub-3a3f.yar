rule TTP_XOR_MULT_DOSStub_3a3f {
  strings:
    $key_3a3f = { 6e 57 [2] 1a 4f [2] 5d 4d [2] 1a 5c [2] 54 50 [2] 58 5a [2] 4f 51 [2] 54 1f [2] 69 }

  condition:
    any of them
}