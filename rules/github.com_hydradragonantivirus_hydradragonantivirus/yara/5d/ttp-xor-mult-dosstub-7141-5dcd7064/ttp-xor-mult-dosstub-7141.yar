rule TTP_XOR_MULT_DOSStub_7141 {
  strings:
    $key_7141 = { 25 29 [2] 51 31 [2] 16 33 [2] 51 22 [2] 1f 2e [2] 13 24 [2] 04 2f [2] 1f 61 [2] 22 }

  condition:
    any of them
}