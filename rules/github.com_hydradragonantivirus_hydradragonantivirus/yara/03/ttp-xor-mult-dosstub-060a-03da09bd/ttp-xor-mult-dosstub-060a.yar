rule TTP_XOR_MULT_DOSStub_060a {
  strings:
    $key_060a = { 52 62 [2] 26 7a [2] 61 78 [2] 26 69 [2] 68 65 [2] 64 6f [2] 73 64 [2] 68 2a [2] 55 }

  condition:
    any of them
}