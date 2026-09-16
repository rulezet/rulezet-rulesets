rule TTP_XOR_MULT_DOSStub_1e7b {
  strings:
    $key_1e7b = { 4a 13 [2] 3e 0b [2] 79 09 [2] 3e 18 [2] 70 14 [2] 7c 1e [2] 6b 15 [2] 70 5b [2] 4d }

  condition:
    any of them
}