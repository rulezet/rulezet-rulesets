rule TTP_XOR_MULT_DOSStub_0716 {
  strings:
    $key_0716 = { 53 7e [2] 27 66 [2] 60 64 [2] 27 75 [2] 69 79 [2] 65 73 [2] 72 78 [2] 69 36 [2] 54 }

  condition:
    any of them
}