rule TTP_XOR_MULT_DOSStub_60e0 {
  strings:
    $key_60e0 = { 34 88 [2] 40 90 [2] 07 92 [2] 40 83 [2] 0e 8f [2] 02 85 [2] 15 8e [2] 0e c0 [2] 33 }

  condition:
    any of them
}