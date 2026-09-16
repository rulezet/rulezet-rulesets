rule TTP_XOR_MULT_DOSStub_3e0a {
  strings:
    $key_3e0a = { 6a 62 [2] 1e 7a [2] 59 78 [2] 1e 69 [2] 50 65 [2] 5c 6f [2] 4b 64 [2] 50 2a [2] 6d }

  condition:
    any of them
}