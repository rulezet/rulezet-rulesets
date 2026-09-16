rule TTP_XOR_MULT_DOSStub_62e0 {
  strings:
    $key_62e0 = { 36 88 [2] 42 90 [2] 05 92 [2] 42 83 [2] 0c 8f [2] 00 85 [2] 17 8e [2] 0c c0 [2] 31 }

  condition:
    any of them
}