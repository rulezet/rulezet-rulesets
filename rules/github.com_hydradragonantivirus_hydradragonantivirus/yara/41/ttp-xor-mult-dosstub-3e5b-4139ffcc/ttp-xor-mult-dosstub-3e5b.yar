rule TTP_XOR_MULT_DOSStub_3e5b {
  strings:
    $key_3e5b = { 6a 33 [2] 1e 2b [2] 59 29 [2] 1e 38 [2] 50 34 [2] 5c 3e [2] 4b 35 [2] 50 7b [2] 6d }

  condition:
    any of them
}