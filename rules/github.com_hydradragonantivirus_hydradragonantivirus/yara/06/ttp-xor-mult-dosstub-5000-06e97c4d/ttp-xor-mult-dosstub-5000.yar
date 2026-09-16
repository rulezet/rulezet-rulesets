rule TTP_XOR_MULT_DOSStub_5000 {
  strings:
    $key_5000 = { 04 68 [2] 70 70 [2] 37 72 [2] 70 63 [2] 3e 6f [2] 32 65 [2] 25 6e [2] 3e 20 [2] 03 }

  condition:
    any of them
}