rule TTP_XOR_MULT_DOSStub_0e1b {
  strings:
    $key_0e1b = { 5a 73 [2] 2e 6b [2] 69 69 [2] 2e 78 [2] 60 74 [2] 6c 7e [2] 7b 75 [2] 60 3b [2] 5d }

  condition:
    any of them
}