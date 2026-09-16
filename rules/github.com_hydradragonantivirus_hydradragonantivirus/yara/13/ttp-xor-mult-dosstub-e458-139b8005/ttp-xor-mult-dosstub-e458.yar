rule TTP_XOR_MULT_DOSStub_e458 {
  strings:
    $key_e458 = { b0 30 [2] c4 28 [2] 83 2a [2] c4 3b [2] 8a 37 [2] 86 3d [2] 91 36 [2] 8a 78 [2] b7 }

  condition:
    any of them
}