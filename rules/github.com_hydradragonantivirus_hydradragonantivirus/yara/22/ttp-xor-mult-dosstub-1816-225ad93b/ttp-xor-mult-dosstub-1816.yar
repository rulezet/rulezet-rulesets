rule TTP_XOR_MULT_DOSStub_1816 {
  strings:
    $key_1816 = { 4c 7e [2] 38 66 [2] 7f 64 [2] 38 75 [2] 76 79 [2] 7a 73 [2] 6d 78 [2] 76 36 [2] 4b }

  condition:
    any of them
}