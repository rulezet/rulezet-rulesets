rule TTP_XOR_MULT_DOSStub_63e0 {
  strings:
    $key_63e0 = { 37 88 [2] 43 90 [2] 04 92 [2] 43 83 [2] 0d 8f [2] 01 85 [2] 16 8e [2] 0d c0 [2] 30 }

  condition:
    any of them
}