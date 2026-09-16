rule TTP_XOR_MULT_DOSStub_e23d {
  strings:
    $key_e23d = { b6 55 [2] c2 4d [2] 85 4f [2] c2 5e [2] 8c 52 [2] 80 58 [2] 97 53 [2] 8c 1d [2] b1 }

  condition:
    any of them
}