rule TTP_XOR_MULT_DOSStub_7100 {
  strings:
    $key_7100 = { 25 68 [2] 51 70 [2] 16 72 [2] 51 63 [2] 1f 6f [2] 13 65 [2] 04 6e [2] 1f 20 [2] 22 }

  condition:
    any of them
}