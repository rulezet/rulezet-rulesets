rule TTP_XOR_MULT_DOSStub_2201 {
  strings:
    $key_2201 = { 76 69 [2] 02 71 [2] 45 73 [2] 02 62 [2] 4c 6e [2] 40 64 [2] 57 6f [2] 4c 21 [2] 71 }

  condition:
    any of them
}