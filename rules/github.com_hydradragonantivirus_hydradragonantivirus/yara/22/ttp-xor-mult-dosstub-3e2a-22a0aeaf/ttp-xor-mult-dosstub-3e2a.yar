rule TTP_XOR_MULT_DOSStub_3e2a {
  strings:
    $key_3e2a = { 6a 42 [2] 1e 5a [2] 59 58 [2] 1e 49 [2] 50 45 [2] 5c 4f [2] 4b 44 [2] 50 0a [2] 6d }

  condition:
    any of them
}