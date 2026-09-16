rule TTP_XOR_MULT_DOSStub_307b {
  strings:
    $key_307b = { 64 13 [2] 10 0b [2] 57 09 [2] 10 18 [2] 5e 14 [2] 52 1e [2] 45 15 [2] 5e 5b [2] 63 }

  condition:
    any of them
}