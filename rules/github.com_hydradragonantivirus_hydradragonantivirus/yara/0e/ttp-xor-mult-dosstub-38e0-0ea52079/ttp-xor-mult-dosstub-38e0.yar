rule TTP_XOR_MULT_DOSStub_38e0 {
  strings:
    $key_38e0 = { 6c 88 [2] 18 90 [2] 5f 92 [2] 18 83 [2] 56 8f [2] 5a 85 [2] 4d 8e [2] 56 c0 [2] 6b }

  condition:
    any of them
}