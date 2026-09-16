rule TTP_XOR_MULT_DOSStub_09e0 {
  strings:
    $key_09e0 = { 5d 88 [2] 29 90 [2] 6e 92 [2] 29 83 [2] 67 8f [2] 6b 85 [2] 7c 8e [2] 67 c0 [2] 5a }

  condition:
    any of them
}