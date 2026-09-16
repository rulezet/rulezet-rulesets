rule TTP_XOR_MULT_DOSStub_e055 {
  strings:
    $key_e055 = { b4 3d [2] c0 25 [2] 87 27 [2] c0 36 [2] 8e 3a [2] 82 30 [2] 95 3b [2] 8e 75 [2] b3 }

  condition:
    any of them
}