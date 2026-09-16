rule TTP_XOR_MULT_DOSStub_747b {
  strings:
    $key_747b = { 20 13 [2] 54 0b [2] 13 09 [2] 54 18 [2] 1a 14 [2] 16 1e [2] 01 15 [2] 1a 5b [2] 27 }

  condition:
    any of them
}