rule TTP_XOR_MULT_DOSStub_e344 {
  strings:
    $key_e344 = { b7 2c [2] c3 34 [2] 84 36 [2] c3 27 [2] 8d 2b [2] 81 21 [2] 96 2a [2] 8d 64 [2] b0 }

  condition:
    any of them
}