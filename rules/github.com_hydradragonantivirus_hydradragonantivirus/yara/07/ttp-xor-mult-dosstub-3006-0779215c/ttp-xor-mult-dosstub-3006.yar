rule TTP_XOR_MULT_DOSStub_3006 {
  strings:
    $key_3006 = { 64 6e [2] 10 76 [2] 57 74 [2] 10 65 [2] 5e 69 [2] 52 63 [2] 45 68 [2] 5e 26 [2] 63 }

  condition:
    any of them
}