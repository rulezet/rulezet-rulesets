rule TTP_XOR_MULT_DOSStub_1e5b {
  strings:
    $key_1e5b = { 4a 33 [2] 3e 2b [2] 79 29 [2] 3e 38 [2] 70 34 [2] 7c 3e [2] 6b 35 [2] 70 7b [2] 4d }

  condition:
    any of them
}