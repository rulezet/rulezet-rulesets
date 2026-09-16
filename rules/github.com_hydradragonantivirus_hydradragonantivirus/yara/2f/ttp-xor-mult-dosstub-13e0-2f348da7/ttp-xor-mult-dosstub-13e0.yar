rule TTP_XOR_MULT_DOSStub_13e0 {
  strings:
    $key_13e0 = { 47 88 [2] 33 90 [2] 74 92 [2] 33 83 [2] 7d 8f [2] 71 85 [2] 66 8e [2] 7d c0 [2] 40 }

  condition:
    any of them
}