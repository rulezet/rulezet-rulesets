rule TTP_XOR_MULT_DOSStub_375b {
  strings:
    $key_375b = { 63 33 [2] 17 2b [2] 50 29 [2] 17 38 [2] 59 34 [2] 55 3e [2] 42 35 [2] 59 7b [2] 64 }

  condition:
    any of them
}