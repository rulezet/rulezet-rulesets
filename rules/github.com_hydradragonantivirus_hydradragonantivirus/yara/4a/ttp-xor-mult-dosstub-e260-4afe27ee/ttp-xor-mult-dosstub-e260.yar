rule TTP_XOR_MULT_DOSStub_e260 {
  strings:
    $key_e260 = { b6 08 [2] c2 10 [2] 85 12 [2] c2 03 [2] 8c 0f [2] 80 05 [2] 97 0e [2] 8c 40 [2] b1 }

  condition:
    any of them
}