rule TTP_XOR_MULT_DOSStub_e338 {
  strings:
    $key_e338 = { b7 50 [2] c3 48 [2] 84 4a [2] c3 5b [2] 8d 57 [2] 81 5d [2] 96 56 [2] 8d 18 [2] b0 }

  condition:
    any of them
}