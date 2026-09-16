rule TTP_XOR_MULT_DOSStub_3e7b {
  strings:
    $key_3e7b = { 6a 13 [2] 1e 0b [2] 59 09 [2] 1e 18 [2] 50 14 [2] 5c 1e [2] 4b 15 [2] 50 5b [2] 6d }

  condition:
    any of them
}