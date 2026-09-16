rule TTP_XOR_MULT_DOSStub_0e3a {
  strings:
    $key_0e3a = { 5a 52 [2] 2e 4a [2] 69 48 [2] 2e 59 [2] 60 55 [2] 6c 5f [2] 7b 54 [2] 60 1a [2] 5d }

  condition:
    any of them
}