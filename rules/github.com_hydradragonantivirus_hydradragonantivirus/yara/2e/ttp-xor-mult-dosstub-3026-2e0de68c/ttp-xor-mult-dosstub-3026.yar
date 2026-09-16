rule TTP_XOR_MULT_DOSStub_3026 {
  strings:
    $key_3026 = { 64 4e [2] 10 56 [2] 57 54 [2] 10 45 [2] 5e 49 [2] 52 43 [2] 45 48 [2] 5e 06 [2] 63 }

  condition:
    any of them
}