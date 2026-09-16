rule TTP_XOR_MULT_DOSStub_294b {
  strings:
    $key_294b = { 7d 23 [2] 09 3b [2] 4e 39 [2] 09 28 [2] 47 24 [2] 4b 2e [2] 5c 25 [2] 47 6b [2] 7a }

  condition:
    any of them
}