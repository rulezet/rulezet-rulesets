rule TTP_XOR_MULT_DOSStub_26e0 {
  strings:
    $key_26e0 = { 72 88 [2] 06 90 [2] 41 92 [2] 06 83 [2] 48 8f [2] 44 85 [2] 53 8e [2] 48 c0 [2] 75 }

  condition:
    any of them
}