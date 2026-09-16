rule TTP_XOR_MULT_DOSStub_e305 {
  strings:
    $key_e305 = { b7 6d [2] c3 75 [2] 84 77 [2] c3 66 [2] 8d 6a [2] 81 60 [2] 96 6b [2] 8d 25 [2] b0 }

  condition:
    any of them
}