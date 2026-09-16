rule TTP_XOR_MULT_DOSStub_e555 {
  strings:
    $key_e555 = { b1 3d [2] c5 25 [2] 82 27 [2] c5 36 [2] 8b 3a [2] 87 30 [2] 90 3b [2] 8b 75 [2] b6 }

  condition:
    any of them
}