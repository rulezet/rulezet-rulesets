rule TTP_XOR_MULT_DOSStub_45e0 {
  strings:
    $key_45e0 = { 11 88 [2] 65 90 [2] 22 92 [2] 65 83 [2] 2b 8f [2] 27 85 [2] 30 8e [2] 2b c0 [2] 16 }

  condition:
    any of them
}