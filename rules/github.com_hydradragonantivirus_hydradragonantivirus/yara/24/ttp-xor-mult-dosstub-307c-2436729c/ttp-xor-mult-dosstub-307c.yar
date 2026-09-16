rule TTP_XOR_MULT_DOSStub_307c {
  strings:
    $key_307c = { 64 14 [2] 10 0c [2] 57 0e [2] 10 1f [2] 5e 13 [2] 52 19 [2] 45 12 [2] 5e 5c [2] 63 }

  condition:
    any of them
}