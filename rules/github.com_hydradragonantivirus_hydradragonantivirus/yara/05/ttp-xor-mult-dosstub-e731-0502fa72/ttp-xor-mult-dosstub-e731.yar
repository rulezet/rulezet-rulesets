rule TTP_XOR_MULT_DOSStub_e731 {
  strings:
    $key_e731 = { b3 59 [2] c7 41 [2] 80 43 [2] c7 52 [2] 89 5e [2] 85 54 [2] 92 5f [2] 89 11 [2] b4 }

  condition:
    any of them
}