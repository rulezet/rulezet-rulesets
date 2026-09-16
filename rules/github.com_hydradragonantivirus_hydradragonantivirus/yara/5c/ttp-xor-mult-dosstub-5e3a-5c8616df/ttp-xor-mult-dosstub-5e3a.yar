rule TTP_XOR_MULT_DOSStub_5e3a {
  strings:
    $key_5e3a = { 0a 52 [2] 7e 4a [2] 39 48 [2] 7e 59 [2] 30 55 [2] 3c 5f [2] 2b 54 [2] 30 1a [2] 0d }

  condition:
    any of them
}