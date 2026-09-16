rule TTP_XOR_MULT_DOSStub_247b {
  strings:
    $key_247b = { 70 13 [2] 04 0b [2] 43 09 [2] 04 18 [2] 4a 14 [2] 46 1e [2] 51 15 [2] 4a 5b [2] 77 }

  condition:
    any of them
}