rule TTP_XOR_MULT_DOSStub_3e5a {
  strings:
    $key_3e5a = { 6a 32 [2] 1e 2a [2] 59 28 [2] 1e 39 [2] 50 35 [2] 5c 3f [2] 4b 34 [2] 50 7a [2] 6d }

  condition:
    any of them
}