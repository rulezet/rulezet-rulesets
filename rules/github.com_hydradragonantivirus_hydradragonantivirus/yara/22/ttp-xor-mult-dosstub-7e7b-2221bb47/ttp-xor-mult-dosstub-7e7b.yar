rule TTP_XOR_MULT_DOSStub_7e7b {
  strings:
    $key_7e7b = { 2a 13 [2] 5e 0b [2] 19 09 [2] 5e 18 [2] 10 14 [2] 1c 1e [2] 0b 15 [2] 10 5b [2] 2d }

  condition:
    any of them
}