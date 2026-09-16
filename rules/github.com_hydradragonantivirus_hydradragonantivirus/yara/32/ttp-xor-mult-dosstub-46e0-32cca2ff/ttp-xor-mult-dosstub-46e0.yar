rule TTP_XOR_MULT_DOSStub_46e0 {
  strings:
    $key_46e0 = { 12 88 [2] 66 90 [2] 21 92 [2] 66 83 [2] 28 8f [2] 24 85 [2] 33 8e [2] 28 c0 [2] 15 }

  condition:
    any of them
}