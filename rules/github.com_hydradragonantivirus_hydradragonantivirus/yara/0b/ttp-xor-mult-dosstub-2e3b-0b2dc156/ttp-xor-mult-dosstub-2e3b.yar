rule TTP_XOR_MULT_DOSStub_2e3b {
  strings:
    $key_2e3b = { 7a 53 [2] 0e 4b [2] 49 49 [2] 0e 58 [2] 40 54 [2] 4c 5e [2] 5b 55 [2] 40 1b [2] 7d }

  condition:
    any of them
}