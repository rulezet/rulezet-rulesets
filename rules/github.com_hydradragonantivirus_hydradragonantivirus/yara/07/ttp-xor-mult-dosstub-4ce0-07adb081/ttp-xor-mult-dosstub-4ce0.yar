rule TTP_XOR_MULT_DOSStub_4ce0 {
  strings:
    $key_4ce0 = { 18 88 [2] 6c 90 [2] 2b 92 [2] 6c 83 [2] 22 8f [2] 2e 85 [2] 39 8e [2] 22 c0 [2] 1f }

  condition:
    any of them
}