rule TTP_XOR_MULT_DOSStub_2e5b {
  strings:
    $key_2e5b = { 7a 33 [2] 0e 2b [2] 49 29 [2] 0e 38 [2] 40 34 [2] 4c 3e [2] 5b 35 [2] 40 7b [2] 7d }

  condition:
    any of them
}