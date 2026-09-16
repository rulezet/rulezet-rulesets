rule TTP_XOR_MULT_DOSStub_7d01 {
  strings:
    $key_7d01 = { 29 69 [2] 5d 71 [2] 1a 73 [2] 5d 62 [2] 13 6e [2] 1f 64 [2] 08 6f [2] 13 21 [2] 2e }

  condition:
    any of them
}