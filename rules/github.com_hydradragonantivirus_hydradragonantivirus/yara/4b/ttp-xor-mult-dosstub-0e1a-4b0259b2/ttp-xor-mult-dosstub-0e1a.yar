rule TTP_XOR_MULT_DOSStub_0e1a {
  strings:
    $key_0e1a = { 5a 72 [2] 2e 6a [2] 69 68 [2] 2e 79 [2] 60 75 [2] 6c 7f [2] 7b 74 [2] 60 3a [2] 5d }

  condition:
    any of them
}