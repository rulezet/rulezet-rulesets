rule TTP_XOR_MULT_DOSStub_e102 {
  strings:
    $key_e102 = { b5 6a [2] c1 72 [2] 86 70 [2] c1 61 [2] 8f 6d [2] 83 67 [2] 94 6c [2] 8f 22 [2] b2 }

  condition:
    any of them
}