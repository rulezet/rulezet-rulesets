rule TTP_XOR_MULT_DOSStub_e15b {
  strings:
    $key_e15b = { b5 33 [2] c1 2b [2] 86 29 [2] c1 38 [2] 8f 34 [2] 83 3e [2] 94 35 [2] 8f 7b [2] b2 }

  condition:
    any of them
}