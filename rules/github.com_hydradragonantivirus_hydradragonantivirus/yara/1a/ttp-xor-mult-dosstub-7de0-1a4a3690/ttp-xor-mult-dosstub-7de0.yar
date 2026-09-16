rule TTP_XOR_MULT_DOSStub_7de0 {
  strings:
    $key_7de0 = { 29 88 [2] 5d 90 [2] 1a 92 [2] 5d 83 [2] 13 8f [2] 1f 85 [2] 08 8e [2] 13 c0 [2] 2e }

  condition:
    any of them
}