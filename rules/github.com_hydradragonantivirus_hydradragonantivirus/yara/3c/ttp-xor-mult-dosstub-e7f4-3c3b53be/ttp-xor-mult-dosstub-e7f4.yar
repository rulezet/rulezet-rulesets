rule TTP_XOR_MULT_DOSStub_e7f4 {
  strings:
    $key_e7f4 = { b3 9c [2] c7 84 [2] 80 86 [2] c7 97 [2] 89 9b [2] 85 91 [2] 92 9a [2] 89 d4 [2] b4 }

  condition:
    any of them
}