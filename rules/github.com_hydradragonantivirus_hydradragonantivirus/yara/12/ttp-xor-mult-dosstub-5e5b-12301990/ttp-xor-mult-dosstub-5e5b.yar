rule TTP_XOR_MULT_DOSStub_5e5b {
  strings:
    $key_5e5b = { 0a 33 [2] 7e 2b [2] 39 29 [2] 7e 38 [2] 30 34 [2] 3c 3e [2] 2b 35 [2] 30 7b [2] 0d }

  condition:
    any of them
}