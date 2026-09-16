rule TTP_XOR_MULT_DOSStub_5e5a {
  strings:
    $key_5e5a = { 0a 32 [2] 7e 2a [2] 39 28 [2] 7e 39 [2] 30 35 [2] 3c 3f [2] 2b 34 [2] 30 7a [2] 0d }

  condition:
    any of them
}