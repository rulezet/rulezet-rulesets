rule TTP_XOR_MULT_DOSStub_6116 {
  strings:
    $key_6116 = { 35 7e [2] 41 66 [2] 06 64 [2] 41 75 [2] 0f 79 [2] 03 73 [2] 14 78 [2] 0f 36 [2] 32 }

  condition:
    any of them
}