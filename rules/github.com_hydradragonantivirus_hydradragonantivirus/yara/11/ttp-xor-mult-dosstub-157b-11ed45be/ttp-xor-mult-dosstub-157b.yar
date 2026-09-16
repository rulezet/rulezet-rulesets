rule TTP_XOR_MULT_DOSStub_157b {
  strings:
    $key_157b = { 41 13 [2] 35 0b [2] 72 09 [2] 35 18 [2] 7b 14 [2] 77 1e [2] 60 15 [2] 7b 5b [2] 46 }

  condition:
    any of them
}