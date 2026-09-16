rule TTP_XOR_MULT_DOSStub_e3f4 {
  strings:
    $key_e3f4 = { b7 9c [2] c3 84 [2] 84 86 [2] c3 97 [2] 8d 9b [2] 81 91 [2] 96 9a [2] 8d d4 [2] b0 }

  condition:
    any of them
}