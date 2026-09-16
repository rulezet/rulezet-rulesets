rule TTP_XOR_MULT_DOSStub_06e0 {
  strings:
    $key_06e0 = { 52 88 [2] 26 90 [2] 61 92 [2] 26 83 [2] 68 8f [2] 64 85 [2] 73 8e [2] 68 c0 [2] 55 }

  condition:
    any of them
}