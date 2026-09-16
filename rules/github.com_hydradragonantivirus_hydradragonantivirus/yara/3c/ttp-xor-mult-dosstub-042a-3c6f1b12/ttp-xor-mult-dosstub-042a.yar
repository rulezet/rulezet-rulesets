rule TTP_XOR_MULT_DOSStub_042a {
  strings:
    $key_042a = { 50 42 [2] 24 5a [2] 63 58 [2] 24 49 [2] 6a 45 [2] 66 4f [2] 71 44 [2] 6a 0a [2] 57 }

  condition:
    any of them
}