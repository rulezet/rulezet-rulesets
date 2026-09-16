rule TTP_XOR_MULT_DOSStub_030a {
  strings:
    $key_030a = { 57 62 [2] 23 7a [2] 64 78 [2] 23 69 [2] 6d 65 [2] 61 6f [2] 76 64 [2] 6d 2a [2] 50 }

  condition:
    any of them
}