rule TTP_XOR_MULT_DOSStub_3b7b {
  strings:
    $key_3b7b = { 6f 13 [2] 1b 0b [2] 5c 09 [2] 1b 18 [2] 55 14 [2] 59 1e [2] 4e 15 [2] 55 5b [2] 68 }

  condition:
    any of them
}