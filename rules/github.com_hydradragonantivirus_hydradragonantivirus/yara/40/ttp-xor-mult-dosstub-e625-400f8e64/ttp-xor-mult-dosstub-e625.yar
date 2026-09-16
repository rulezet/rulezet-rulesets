rule TTP_XOR_MULT_DOSStub_e625 {
  strings:
    $key_e625 = { b2 4d [2] c6 55 [2] 81 57 [2] c6 46 [2] 88 4a [2] 84 40 [2] 93 4b [2] 88 05 [2] b5 }

  condition:
    any of them
}