rule TTP_XOR_MULT_DOSStub_31e0 {
  strings:
    $key_31e0 = { 65 88 [2] 11 90 [2] 56 92 [2] 11 83 [2] 5f 8f [2] 53 85 [2] 44 8e [2] 5f c0 [2] 62 }

  condition:
    any of them
}