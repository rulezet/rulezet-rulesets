rule TTP_XOR_MULT_DOSStub_33e0 {
  strings:
    $key_33e0 = { 67 88 [2] 13 90 [2] 54 92 [2] 13 83 [2] 5d 8f [2] 51 85 [2] 46 8e [2] 5d c0 [2] 60 }

  condition:
    any of them
}