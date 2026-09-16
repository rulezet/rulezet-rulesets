rule TTP_XOR_MULT_DOSStub_5d01 {
  strings:
    $key_5d01 = { 09 69 [2] 7d 71 [2] 3a 73 [2] 7d 62 [2] 33 6e [2] 3f 64 [2] 28 6f [2] 33 21 [2] 0e }

  condition:
    any of them
}