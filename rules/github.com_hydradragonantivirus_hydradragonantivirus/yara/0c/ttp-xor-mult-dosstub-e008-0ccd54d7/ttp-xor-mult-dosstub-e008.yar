rule TTP_XOR_MULT_DOSStub_e008 {
  strings:
    $key_e008 = { b4 60 [2] c0 78 [2] 87 7a [2] c0 6b [2] 8e 67 [2] 82 6d [2] 95 66 [2] 8e 28 [2] b3 }

  condition:
    any of them
}