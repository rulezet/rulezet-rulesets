rule TTP_XOR_MULT_DOSStub_3206 {
  strings:
    $key_3206 = { 66 6e [2] 12 76 [2] 55 74 [2] 12 65 [2] 5c 69 [2] 50 63 [2] 47 68 [2] 5c 26 [2] 61 }

  condition:
    any of them
}