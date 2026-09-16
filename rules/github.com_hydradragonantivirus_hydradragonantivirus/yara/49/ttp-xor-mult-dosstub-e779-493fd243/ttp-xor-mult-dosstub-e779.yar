rule TTP_XOR_MULT_DOSStub_e779 {
  strings:
    $key_e779 = { b3 11 [2] c7 09 [2] 80 0b [2] c7 1a [2] 89 16 [2] 85 1c [2] 92 17 [2] 89 59 [2] b4 }

  condition:
    any of them
}