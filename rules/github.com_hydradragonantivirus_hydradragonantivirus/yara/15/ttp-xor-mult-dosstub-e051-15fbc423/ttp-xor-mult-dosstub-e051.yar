rule TTP_XOR_MULT_DOSStub_e051 {
  strings:
    $key_e051 = { b4 39 [2] c0 21 [2] 87 23 [2] c0 32 [2] 8e 3e [2] 82 34 [2] 95 3f [2] 8e 71 [2] b3 }

  condition:
    any of them
}