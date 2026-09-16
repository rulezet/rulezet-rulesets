rule TTP_XOR_MULT_DOSStub_7101 {
  strings:
    $key_7101 = { 25 69 [2] 51 71 [2] 16 73 [2] 51 62 [2] 1f 6e [2] 13 64 [2] 04 6f [2] 1f 21 [2] 22 }

  condition:
    any of them
}