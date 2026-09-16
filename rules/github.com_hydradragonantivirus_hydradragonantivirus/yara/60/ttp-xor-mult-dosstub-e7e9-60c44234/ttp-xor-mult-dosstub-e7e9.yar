rule TTP_XOR_MULT_DOSStub_e7e9 {
  strings:
    $key_e7e9 = { b3 81 [2] c7 99 [2] 80 9b [2] c7 8a [2] 89 86 [2] 85 8c [2] 92 87 [2] 89 c9 [2] b4 }

  condition:
    any of them
}