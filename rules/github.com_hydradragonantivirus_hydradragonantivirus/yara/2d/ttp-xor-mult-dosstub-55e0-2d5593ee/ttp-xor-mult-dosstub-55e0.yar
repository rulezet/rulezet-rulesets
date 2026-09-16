rule TTP_XOR_MULT_DOSStub_55e0 {
  strings:
    $key_55e0 = { 01 88 [2] 75 90 [2] 32 92 [2] 75 83 [2] 3b 8f [2] 37 85 [2] 20 8e [2] 3b c0 [2] 06 }

  condition:
    any of them
}