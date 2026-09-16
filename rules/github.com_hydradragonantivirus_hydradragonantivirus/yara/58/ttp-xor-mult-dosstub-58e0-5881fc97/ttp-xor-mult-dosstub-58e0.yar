rule TTP_XOR_MULT_DOSStub_58e0 {
  strings:
    $key_58e0 = { 0c 88 [2] 78 90 [2] 3f 92 [2] 78 83 [2] 36 8f [2] 3a 85 [2] 2d 8e [2] 36 c0 [2] 0b }

  condition:
    any of them
}