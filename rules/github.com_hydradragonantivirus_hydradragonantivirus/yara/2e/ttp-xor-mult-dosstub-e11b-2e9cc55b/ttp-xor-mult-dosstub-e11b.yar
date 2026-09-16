rule TTP_XOR_MULT_DOSStub_e11b {
  strings:
    $key_e11b = { b5 73 [2] c1 6b [2] 86 69 [2] c1 78 [2] 8f 74 [2] 83 7e [2] 94 75 [2] 8f 3b [2] b2 }

  condition:
    any of them
}