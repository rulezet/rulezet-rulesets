rule TTP_XOR_MULT_DOSStub_07e0 {
  strings:
    $key_07e0 = { 53 88 [2] 27 90 [2] 60 92 [2] 27 83 [2] 69 8f [2] 65 85 [2] 72 8e [2] 69 c0 [2] 54 }

  condition:
    any of them
}