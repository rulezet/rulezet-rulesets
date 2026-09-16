rule TTP_XOR_MULT_DOSStub_2601 {
  strings:
    $key_2601 = { 72 69 [2] 06 71 [2] 41 73 [2] 06 62 [2] 48 6e [2] 44 64 [2] 53 6f [2] 48 21 [2] 75 }

  condition:
    any of them
}