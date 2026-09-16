rule TTP_XOR_MULT_DOSStub_2701 {
  strings:
    $key_2701 = { 73 69 [2] 07 71 [2] 40 73 [2] 07 62 [2] 49 6e [2] 45 64 [2] 52 6f [2] 49 21 [2] 74 }

  condition:
    any of them
}