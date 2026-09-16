rule TTP_XOR_MULT_DOSStub_e158 {
  strings:
    $key_e158 = { b5 30 [2] c1 28 [2] 86 2a [2] c1 3b [2] 8f 37 [2] 83 3d [2] 94 36 [2] 8f 78 [2] b2 }

  condition:
    any of them
}