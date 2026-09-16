rule TTP_XOR_MULT_DOSStub_71e0 {
  strings:
    $key_71e0 = { 25 88 [2] 51 90 [2] 16 92 [2] 51 83 [2] 1f 8f [2] 13 85 [2] 04 8e [2] 1f c0 [2] 22 }

  condition:
    any of them
}