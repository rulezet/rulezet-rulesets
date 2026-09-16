rule TTP_XOR_MULT_DOSStub_2217 {
  strings:
    $key_2217 = { 76 7f [2] 02 67 [2] 45 65 [2] 02 74 [2] 4c 78 [2] 40 72 [2] 57 79 [2] 4c 37 [2] 71 }

  condition:
    any of them
}