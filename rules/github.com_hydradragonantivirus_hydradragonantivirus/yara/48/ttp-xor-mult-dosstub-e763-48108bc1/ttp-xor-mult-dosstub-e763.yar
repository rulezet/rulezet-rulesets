rule TTP_XOR_MULT_DOSStub_e763 {
  strings:
    $key_e763 = { b3 0b [2] c7 13 [2] 80 11 [2] c7 00 [2] 89 0c [2] 85 06 [2] 92 0d [2] 89 43 [2] b4 }

  condition:
    any of them
}