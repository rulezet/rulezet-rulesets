rule TTP_XOR_MULT_DOSStub_1ae0 {
  strings:
    $key_1ae0 = { 4e 88 [2] 3a 90 [2] 7d 92 [2] 3a 83 [2] 74 8f [2] 78 85 [2] 6f 8e [2] 74 c0 [2] 49 }

  condition:
    any of them
}