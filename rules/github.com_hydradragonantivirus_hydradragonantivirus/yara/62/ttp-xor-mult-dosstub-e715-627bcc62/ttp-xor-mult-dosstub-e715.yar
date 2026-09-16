rule TTP_XOR_MULT_DOSStub_e715 {
  strings:
    $key_e715 = { b3 7d [2] c7 65 [2] 80 67 [2] c7 76 [2] 89 7a [2] 85 70 [2] 92 7b [2] 89 35 [2] b4 }

  condition:
    any of them
}