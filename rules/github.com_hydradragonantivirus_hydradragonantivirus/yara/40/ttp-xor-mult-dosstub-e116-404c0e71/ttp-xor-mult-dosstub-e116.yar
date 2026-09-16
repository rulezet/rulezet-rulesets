rule TTP_XOR_MULT_DOSStub_e116 {
  strings:
    $key_e116 = { b5 7e [2] c1 66 [2] 86 64 [2] c1 75 [2] 8f 79 [2] 83 73 [2] 94 78 [2] 8f 36 [2] b2 }

  condition:
    any of them
}