rule TTP_XOR_MULT_DOSStub_0101 {
  strings:
    $key_0101 = { 55 69 [2] 21 71 [2] 66 73 [2] 21 62 [2] 6f 6e [2] 63 64 [2] 74 6f [2] 6f 21 [2] 52 }

  condition:
    any of them
}