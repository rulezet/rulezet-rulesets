rule TTP_XOR_MULT_DOSStub_76e0 {
  strings:
    $key_76e0 = { 22 88 [2] 56 90 [2] 11 92 [2] 56 83 [2] 18 8f [2] 14 85 [2] 03 8e [2] 18 c0 [2] 25 }

  condition:
    any of them
}