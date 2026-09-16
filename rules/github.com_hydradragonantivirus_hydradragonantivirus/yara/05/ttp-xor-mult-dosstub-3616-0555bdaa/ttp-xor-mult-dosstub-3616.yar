rule TTP_XOR_MULT_DOSStub_3616 {
  strings:
    $key_3616 = { 62 7e [2] 16 66 [2] 51 64 [2] 16 75 [2] 58 79 [2] 54 73 [2] 43 78 [2] 58 36 [2] 65 }

  condition:
    any of them
}