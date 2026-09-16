rule TTP_XOR_MULT_DOSStub_30e0 {
  strings:
    $key_30e0 = { 64 88 [2] 10 90 [2] 57 92 [2] 10 83 [2] 5e 8f [2] 52 85 [2] 45 8e [2] 5e c0 [2] 63 }

  condition:
    any of them
}