rule TTP_XOR_MULT_DOSStub_e755 {
  strings:
    $key_e755 = { b3 3d [2] c7 25 [2] 80 27 [2] c7 36 [2] 89 3a [2] 85 30 [2] 92 3b [2] 89 75 [2] b4 }

  condition:
    any of them
}