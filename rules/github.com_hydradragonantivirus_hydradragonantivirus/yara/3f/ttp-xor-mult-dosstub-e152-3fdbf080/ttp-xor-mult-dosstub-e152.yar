rule TTP_XOR_MULT_DOSStub_e152 {
  strings:
    $key_e152 = { b5 3a [2] c1 22 [2] 86 20 [2] c1 31 [2] 8f 3d [2] 83 37 [2] 94 3c [2] 8f 72 [2] b2 }

  condition:
    any of them
}