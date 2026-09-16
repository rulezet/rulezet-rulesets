rule TTP_XOR_MULT_DOSStub_2216 {
  strings:
    $key_2216 = { 76 7e [2] 02 66 [2] 45 64 [2] 02 75 [2] 4c 79 [2] 40 73 [2] 57 78 [2] 4c 36 [2] 71 }

  condition:
    any of them
}