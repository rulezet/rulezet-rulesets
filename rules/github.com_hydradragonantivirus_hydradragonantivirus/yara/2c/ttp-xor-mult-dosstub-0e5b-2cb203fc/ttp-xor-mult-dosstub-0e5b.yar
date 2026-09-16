rule TTP_XOR_MULT_DOSStub_0e5b {
  strings:
    $key_0e5b = { 5a 33 [2] 2e 2b [2] 69 29 [2] 2e 38 [2] 60 34 [2] 6c 3e [2] 7b 35 [2] 60 7b [2] 5d }

  condition:
    any of them
}