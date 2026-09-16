rule TTP_XOR_MULT_DOSStub_e2f4 {
  strings:
    $key_e2f4 = { b6 9c [2] c2 84 [2] 85 86 [2] c2 97 [2] 8c 9b [2] 80 91 [2] 97 9a [2] 8c d4 [2] b1 }

  condition:
    any of them
}