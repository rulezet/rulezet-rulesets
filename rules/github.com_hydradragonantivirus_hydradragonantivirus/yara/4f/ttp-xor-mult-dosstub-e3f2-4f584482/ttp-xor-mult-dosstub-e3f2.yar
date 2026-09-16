rule TTP_XOR_MULT_DOSStub_e3f2 {
  strings:
    $key_e3f2 = { b7 9a [2] c3 82 [2] 84 80 [2] c3 91 [2] 8d 9d [2] 81 97 [2] 96 9c [2] 8d d2 [2] b0 }

  condition:
    any of them
}