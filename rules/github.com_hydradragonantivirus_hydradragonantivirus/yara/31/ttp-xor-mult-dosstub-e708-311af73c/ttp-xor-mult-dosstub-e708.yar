rule TTP_XOR_MULT_DOSStub_e708 {
  strings:
    $key_e708 = { b3 60 [2] c7 78 [2] 80 7a [2] c7 6b [2] 89 67 [2] 85 6d [2] 92 66 [2] 89 28 [2] b4 }

  condition:
    any of them
}