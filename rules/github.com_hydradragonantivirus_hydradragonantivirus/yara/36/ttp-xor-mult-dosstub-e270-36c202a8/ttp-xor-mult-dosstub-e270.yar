rule TTP_XOR_MULT_DOSStub_e270 {
  strings:
    $key_e270 = { b6 18 [2] c2 00 [2] 85 02 [2] c2 13 [2] 8c 1f [2] 80 15 [2] 97 1e [2] 8c 50 [2] b1 }

  condition:
    any of them
}