rule TTP_XOR_MULT_DOSStub_577b {
  strings:
    $key_577b = { 03 13 [2] 77 0b [2] 30 09 [2] 77 18 [2] 39 14 [2] 35 1e [2] 22 15 [2] 39 5b [2] 04 }

  condition:
    any of them
}