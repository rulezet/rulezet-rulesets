rule TTP_XOR_MULT_DOSStub_1e3b {
  strings:
    $key_1e3b = { 4a 53 [2] 3e 4b [2] 79 49 [2] 3e 58 [2] 70 54 [2] 7c 5e [2] 6b 55 [2] 70 1b [2] 4d }

  condition:
    any of them
}