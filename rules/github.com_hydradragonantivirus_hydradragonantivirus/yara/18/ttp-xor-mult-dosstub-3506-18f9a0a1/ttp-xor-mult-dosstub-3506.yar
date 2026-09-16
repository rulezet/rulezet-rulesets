rule TTP_XOR_MULT_DOSStub_3506 {
  strings:
    $key_3506 = { 61 6e [2] 15 76 [2] 52 74 [2] 15 65 [2] 5b 69 [2] 57 63 [2] 40 68 [2] 5b 26 [2] 66 }

  condition:
    any of them
}