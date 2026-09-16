rule TTP_XOR_MULT_DOSStub_e602 {
  strings:
    $key_e602 = { b2 6a [2] c6 72 [2] 81 70 [2] c6 61 [2] 88 6d [2] 84 67 [2] 93 6c [2] 88 22 [2] b5 }

  condition:
    any of them
}