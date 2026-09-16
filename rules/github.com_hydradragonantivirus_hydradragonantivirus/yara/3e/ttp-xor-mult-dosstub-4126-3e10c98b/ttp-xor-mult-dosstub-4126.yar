rule TTP_XOR_MULT_DOSStub_4126 {
  strings:
    $key_4126 = { 15 4e [2] 61 56 [2] 26 54 [2] 61 45 [2] 2f 49 [2] 23 43 [2] 34 48 [2] 2f 06 [2] 12 }

  condition:
    any of them
}