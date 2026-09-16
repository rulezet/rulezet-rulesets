rule TTP_XOR_MULT_DOSStub_e048 {
  strings:
    $key_e048 = { b4 20 [2] c0 38 [2] 87 3a [2] c0 2b [2] 8e 27 [2] 82 2d [2] 95 26 [2] 8e 68 [2] b3 }

  condition:
    any of them
}