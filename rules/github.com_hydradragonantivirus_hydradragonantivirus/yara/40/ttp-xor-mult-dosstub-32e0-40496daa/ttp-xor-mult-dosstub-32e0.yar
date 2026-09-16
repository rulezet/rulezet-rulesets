rule TTP_XOR_MULT_DOSStub_32e0 {
  strings:
    $key_32e0 = { 66 88 [2] 12 90 [2] 55 92 [2] 12 83 [2] 5c 8f [2] 50 85 [2] 47 8e [2] 5c c0 [2] 61 }

  condition:
    any of them
}