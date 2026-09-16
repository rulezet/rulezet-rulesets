rule TTP_XOR_MULT_DOSStub_e316 {
  strings:
    $key_e316 = { b7 7e [2] c3 66 [2] 84 64 [2] c3 75 [2] 8d 79 [2] 81 73 [2] 96 78 [2] 8d 36 [2] b0 }

  condition:
    any of them
}