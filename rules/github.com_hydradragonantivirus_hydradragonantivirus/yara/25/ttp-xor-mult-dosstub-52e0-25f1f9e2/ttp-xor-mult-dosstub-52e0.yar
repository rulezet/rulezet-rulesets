rule TTP_XOR_MULT_DOSStub_52e0 {
  strings:
    $key_52e0 = { 06 88 [2] 72 90 [2] 35 92 [2] 72 83 [2] 3c 8f [2] 30 85 [2] 27 8e [2] 3c c0 [2] 01 }

  condition:
    any of them
}