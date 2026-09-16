rule TTP_XOR_MULT_DOSStub_6800 {
  strings:
    $key_6800 = { 3c 68 [2] 48 70 [2] 0f 72 [2] 48 63 [2] 06 6f [2] 0a 65 [2] 1d 6e [2] 06 20 [2] 3b }

  condition:
    any of them
}