rule TTP_XOR_MULT_DOSStub_e359 {
  strings:
    $key_e359 = { b7 31 [2] c3 29 [2] 84 2b [2] c3 3a [2] 8d 36 [2] 81 3c [2] 96 37 [2] 8d 79 [2] b0 }

  condition:
    any of them
}