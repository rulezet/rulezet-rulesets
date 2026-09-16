rule TTP_XOR_MULT_DOSStub_08e0 {
  strings:
    $key_08e0 = { 5c 88 [2] 28 90 [2] 6f 92 [2] 28 83 [2] 66 8f [2] 6a 85 [2] 7d 8e [2] 66 c0 [2] 5b }

  condition:
    any of them
}