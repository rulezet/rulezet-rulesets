rule TTP_XOR_MULT_DOSStub_5d00 {
  strings:
    $key_5d00 = { 09 68 [2] 7d 70 [2] 3a 72 [2] 7d 63 [2] 33 6f [2] 3f 65 [2] 28 6e [2] 33 20 [2] 0e }

  condition:
    any of them
}