rule TTP_XOR_MULT_DOSStub_e200 {
  strings:
    $key_e200 = { b6 68 [2] c2 70 [2] 85 72 [2] c2 63 [2] 8c 6f [2] 80 65 [2] 97 6e [2] 8c 20 [2] b1 }

  condition:
    any of them
}