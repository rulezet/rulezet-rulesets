rule TTP_XOR_MULT_DOSStub_e721 {
  strings:
    $key_e721 = { b3 49 [2] c7 51 [2] 80 53 [2] c7 42 [2] 89 4e [2] 85 44 [2] 92 4f [2] 89 01 [2] b4 }

  condition:
    any of them
}