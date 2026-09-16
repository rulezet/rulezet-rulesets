rule TTP_XOR_MULT_DOSStub_4d01 {
  strings:
    $key_4d01 = { 19 69 [2] 6d 71 [2] 2a 73 [2] 6d 62 [2] 23 6e [2] 2f 64 [2] 38 6f [2] 23 21 [2] 1e }

  condition:
    any of them
}