rule TTP_XOR_MULT_DOSStub_0e0a {
  strings:
    $key_0e0a = { 5a 62 [2] 2e 7a [2] 69 78 [2] 2e 69 [2] 60 65 [2] 6c 6f [2] 7b 64 [2] 60 2a [2] 5d }

  condition:
    any of them
}