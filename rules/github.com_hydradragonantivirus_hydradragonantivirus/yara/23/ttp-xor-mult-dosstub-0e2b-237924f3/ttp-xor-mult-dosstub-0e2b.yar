rule TTP_XOR_MULT_DOSStub_0e2b {
  strings:
    $key_0e2b = { 5a 43 [2] 2e 5b [2] 69 59 [2] 2e 48 [2] 60 44 [2] 6c 4e [2] 7b 45 [2] 60 0b [2] 5d }

  condition:
    any of them
}