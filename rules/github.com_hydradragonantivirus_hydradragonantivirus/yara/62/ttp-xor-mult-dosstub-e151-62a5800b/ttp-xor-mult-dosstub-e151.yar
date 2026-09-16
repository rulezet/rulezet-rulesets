rule TTP_XOR_MULT_DOSStub_e151 {
  strings:
    $key_e151 = { b5 39 [2] c1 21 [2] 86 23 [2] c1 32 [2] 8f 3e [2] 83 34 [2] 94 3f [2] 8f 71 [2] b2 }

  condition:
    any of them
}