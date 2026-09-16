rule TTP_XOR_MULT_DOSStub_e2f8 {
  strings:
    $key_e2f8 = { b6 90 [2] c2 88 [2] 85 8a [2] c2 9b [2] 8c 97 [2] 80 9d [2] 97 96 [2] 8c d8 [2] b1 }

  condition:
    any of them
}