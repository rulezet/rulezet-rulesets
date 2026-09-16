rule TTP_XOR_MULT_DOSStub_e768 {
  strings:
    $key_e768 = { b3 00 [2] c7 18 [2] 80 1a [2] c7 0b [2] 89 07 [2] 85 0d [2] 92 06 [2] 89 48 [2] b4 }

  condition:
    any of them
}