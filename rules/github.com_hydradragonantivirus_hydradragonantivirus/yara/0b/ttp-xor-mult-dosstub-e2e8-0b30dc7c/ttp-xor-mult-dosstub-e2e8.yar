rule TTP_XOR_MULT_DOSStub_e2e8 {
  strings:
    $key_e2e8 = { b6 80 [2] c2 98 [2] 85 9a [2] c2 8b [2] 8c 87 [2] 80 8d [2] 97 86 [2] 8c c8 [2] b1 }

  condition:
    any of them
}