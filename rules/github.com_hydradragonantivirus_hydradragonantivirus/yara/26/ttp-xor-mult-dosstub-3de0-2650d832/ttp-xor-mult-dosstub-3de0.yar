rule TTP_XOR_MULT_DOSStub_3de0 {
  strings:
    $key_3de0 = { 69 88 [2] 1d 90 [2] 5a 92 [2] 1d 83 [2] 53 8f [2] 5f 85 [2] 48 8e [2] 53 c0 [2] 6e }

  condition:
    any of them
}