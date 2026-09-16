rule TTP_XOR_MULT_DOSStub_7140 {
  strings:
    $key_7140 = { 25 28 [2] 51 30 [2] 16 32 [2] 51 23 [2] 1f 2f [2] 13 25 [2] 04 2e [2] 1f 60 [2] 22 }

  condition:
    any of them
}