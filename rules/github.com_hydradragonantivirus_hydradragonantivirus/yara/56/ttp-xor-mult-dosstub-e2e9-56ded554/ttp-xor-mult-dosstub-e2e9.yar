rule TTP_XOR_MULT_DOSStub_e2e9 {
  strings:
    $key_e2e9 = { b6 81 [2] c2 99 [2] 85 9b [2] c2 8a [2] 8c 86 [2] 80 8c [2] 97 87 [2] 8c c9 [2] b1 }

  condition:
    any of them
}