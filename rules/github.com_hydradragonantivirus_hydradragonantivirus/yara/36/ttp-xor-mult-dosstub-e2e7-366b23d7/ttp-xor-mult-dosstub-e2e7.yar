rule TTP_XOR_MULT_DOSStub_e2e7 {
  strings:
    $key_e2e7 = { b6 8f [2] c2 97 [2] 85 95 [2] c2 84 [2] 8c 88 [2] 80 82 [2] 97 89 [2] 8c c7 [2] b1 }

  condition:
    any of them
}