rule TTP_XOR_MULT_DOSStub_e308 {
  strings:
    $key_e308 = { b7 60 [2] c3 78 [2] 84 7a [2] c3 6b [2] 8d 67 [2] 81 6d [2] 96 66 [2] 8d 28 [2] b0 }

  condition:
    any of them
}