rule TTP_XOR_MULT_DOSStub_68e0 {
  strings:
    $key_68e0 = { 3c 88 [2] 48 90 [2] 0f 92 [2] 48 83 [2] 06 8f [2] 0a 85 [2] 1d 8e [2] 06 c0 [2] 3b }

  condition:
    any of them
}