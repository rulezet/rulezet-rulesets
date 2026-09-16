rule TTP_XOR_MULT_DOSStub_17e0 {
  strings:
    $key_17e0 = { 43 88 [2] 37 90 [2] 70 92 [2] 37 83 [2] 79 8f [2] 75 85 [2] 62 8e [2] 79 c0 [2] 44 }

  condition:
    any of them
}