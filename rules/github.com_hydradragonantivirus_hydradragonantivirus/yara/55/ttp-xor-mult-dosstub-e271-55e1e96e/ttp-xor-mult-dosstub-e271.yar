rule TTP_XOR_MULT_DOSStub_e271 {
  strings:
    $key_e271 = { b6 19 [2] c2 01 [2] 85 03 [2] c2 12 [2] 8c 1e [2] 80 14 [2] 97 1f [2] 8c 51 [2] b1 }

  condition:
    any of them
}