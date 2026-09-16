rule TTP_XOR_MULT_DOSStub_e314 {
  strings:
    $key_e314 = { b7 7c [2] c3 64 [2] 84 66 [2] c3 77 [2] 8d 7b [2] 81 71 [2] 96 7a [2] 8d 34 [2] b0 }

  condition:
    any of them
}