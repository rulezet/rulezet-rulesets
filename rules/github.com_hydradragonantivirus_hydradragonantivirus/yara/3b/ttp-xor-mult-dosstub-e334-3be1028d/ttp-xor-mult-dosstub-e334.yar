rule TTP_XOR_MULT_DOSStub_e334 {
  strings:
    $key_e334 = { b7 5c [2] c3 44 [2] 84 46 [2] c3 57 [2] 8d 5b [2] 81 51 [2] 96 5a [2] 8d 14 [2] b0 }

  condition:
    any of them
}