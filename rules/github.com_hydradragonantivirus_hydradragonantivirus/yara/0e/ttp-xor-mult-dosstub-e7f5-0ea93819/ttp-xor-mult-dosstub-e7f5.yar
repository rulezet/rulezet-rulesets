rule TTP_XOR_MULT_DOSStub_e7f5 {
  strings:
    $key_e7f5 = { b3 9d [2] c7 85 [2] 80 87 [2] c7 96 [2] 89 9a [2] 85 90 [2] 92 9b [2] 89 d5 [2] b4 }

  condition:
    any of them
}