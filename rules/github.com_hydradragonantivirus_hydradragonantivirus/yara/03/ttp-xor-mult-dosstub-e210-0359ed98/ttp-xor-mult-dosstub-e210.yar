rule TTP_XOR_MULT_DOSStub_e210 {
  strings:
    $key_e210 = { b6 78 [2] c2 60 [2] 85 62 [2] c2 73 [2] 8c 7f [2] 80 75 [2] 97 7e [2] 8c 30 [2] b1 }

  condition:
    any of them
}