rule TTP_XOR_MULT_DOSStub_e058 {
  strings:
    $key_e058 = { b4 30 [2] c0 28 [2] 87 2a [2] c0 3b [2] 8e 37 [2] 82 3d [2] 95 36 [2] 8e 78 [2] b3 }

  condition:
    any of them
}