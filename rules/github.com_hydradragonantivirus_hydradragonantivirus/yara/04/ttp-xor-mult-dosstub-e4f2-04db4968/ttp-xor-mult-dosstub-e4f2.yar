rule TTP_XOR_MULT_DOSStub_e4f2 {
  strings:
    $key_e4f2 = { b0 9a [2] c4 82 [2] 83 80 [2] c4 91 [2] 8a 9d [2] 86 97 [2] 91 9c [2] 8a d2 [2] b7 }

  condition:
    any of them
}