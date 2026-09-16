rule TTP_XOR_MULT_DOSStub_e7e7 {
  strings:
    $key_e7e7 = { b3 8f [2] c7 97 [2] 80 95 [2] c7 84 [2] 89 88 [2] 85 82 [2] 92 89 [2] 89 c7 [2] b4 }

  condition:
    any of them
}