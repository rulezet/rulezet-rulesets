rule TTP_XOR_MULT_DOSStub_e312 {
  strings:
    $key_e312 = { b7 7a [2] c3 62 [2] 84 60 [2] c3 71 [2] 8d 7d [2] 81 77 [2] 96 7c [2] 8d 32 [2] b0 }

  condition:
    any of them
}