rule TTP_XOR_MULT_DOSStub_1601 {
  strings:
    $key_1601 = { 42 69 [2] 36 71 [2] 71 73 [2] 36 62 [2] 78 6e [2] 74 64 [2] 63 6f [2] 78 21 [2] 45 }

  condition:
    any of them
}