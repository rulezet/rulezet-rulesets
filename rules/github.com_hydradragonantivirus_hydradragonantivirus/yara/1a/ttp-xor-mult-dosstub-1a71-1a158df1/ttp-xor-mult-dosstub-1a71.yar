rule TTP_XOR_MULT_DOSStub_1a71 {
  strings:
    $key_1a71 = { 4e 19 [2] 3a 01 [2] 7d 03 [2] 3a 12 [2] 74 1e [2] 78 14 [2] 6f 1f [2] 74 51 [2] 49 }

  condition:
    any of them
}