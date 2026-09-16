rule TTP_XOR_MULT_DOSStub_670a {
  strings:
    $key_670a = { 33 62 [2] 47 7a [2] 00 78 [2] 47 69 [2] 09 65 [2] 05 6f [2] 12 64 [2] 09 2a [2] 34 }

  condition:
    any of them
}