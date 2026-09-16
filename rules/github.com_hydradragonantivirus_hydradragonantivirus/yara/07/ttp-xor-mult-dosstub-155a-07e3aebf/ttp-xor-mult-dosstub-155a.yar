rule TTP_XOR_MULT_DOSStub_155a {
  strings:
    $key_155a = { 41 32 [2] 35 2a [2] 72 28 [2] 35 39 [2] 7b 35 [2] 77 3f [2] 60 34 [2] 7b 7a [2] 46 }

  condition:
    any of them
}