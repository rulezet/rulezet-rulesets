rule TTP_XOR_MULT_DOSStub_e263 {
  strings:
    $key_e263 = { b6 0b [2] c2 13 [2] 85 11 [2] c2 00 [2] 8c 0c [2] 80 06 [2] 97 0d [2] 8c 43 [2] b1 }

  condition:
    any of them
}