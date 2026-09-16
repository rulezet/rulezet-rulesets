rule TTP_XOR_MULT_DOSStub_e261 {
  strings:
    $key_e261 = { b6 09 [2] c2 11 [2] 85 13 [2] c2 02 [2] 8c 0e [2] 80 04 [2] 97 0f [2] 8c 41 [2] b1 }

  condition:
    any of them
}