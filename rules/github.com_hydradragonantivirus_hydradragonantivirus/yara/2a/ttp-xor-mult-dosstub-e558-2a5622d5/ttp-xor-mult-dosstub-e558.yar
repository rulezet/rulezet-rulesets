rule TTP_XOR_MULT_DOSStub_e558 {
  strings:
    $key_e558 = { b1 30 [2] c5 28 [2] 82 2a [2] c5 3b [2] 8b 37 [2] 87 3d [2] 90 36 [2] 8b 78 [2] b6 }

  condition:
    any of them
}