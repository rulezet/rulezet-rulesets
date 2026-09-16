rule TTP_XOR_MULT_DOSStub_e5f4 {
  strings:
    $key_e5f4 = { b1 9c [2] c5 84 [2] 82 86 [2] c5 97 [2] 8b 9b [2] 87 91 [2] 90 9a [2] 8b d4 [2] b6 }

  condition:
    any of them
}