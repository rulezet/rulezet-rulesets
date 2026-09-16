rule TTP_XOR_MULT_DOSStub_04e0 {
  strings:
    $key_04e0 = { 50 88 [2] 24 90 [2] 63 92 [2] 24 83 [2] 6a 8f [2] 66 85 [2] 71 8e [2] 6a c0 [2] 57 }

  condition:
    any of them
}