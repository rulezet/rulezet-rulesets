rule TTP_XOR_MULT_DOSStub_2101 {
  strings:
    $key_2101 = { 75 69 [2] 01 71 [2] 46 73 [2] 01 62 [2] 4f 6e [2] 43 64 [2] 54 6f [2] 4f 21 [2] 72 }

  condition:
    any of them
}