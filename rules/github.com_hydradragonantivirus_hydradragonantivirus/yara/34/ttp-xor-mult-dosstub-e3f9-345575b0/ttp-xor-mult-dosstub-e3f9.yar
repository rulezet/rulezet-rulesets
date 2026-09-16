rule TTP_XOR_MULT_DOSStub_e3f9 {
  strings:
    $key_e3f9 = { b7 91 [2] c3 89 [2] 84 8b [2] c3 9a [2] 8d 96 [2] 81 9c [2] 96 97 [2] 8d d9 [2] b0 }

  condition:
    any of them
}