rule TTP_XOR_MULT_DOSStub_2e1b {
  strings:
    $key_2e1b = { 7a 73 [2] 0e 6b [2] 49 69 [2] 0e 78 [2] 40 74 [2] 4c 7e [2] 5b 75 [2] 40 3b [2] 7d }

  condition:
    any of them
}