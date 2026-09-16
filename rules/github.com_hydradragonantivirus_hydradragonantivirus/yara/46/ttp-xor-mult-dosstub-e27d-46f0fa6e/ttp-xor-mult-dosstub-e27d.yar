rule TTP_XOR_MULT_DOSStub_e27d {
  strings:
    $key_e27d = { b6 15 [2] c2 0d [2] 85 0f [2] c2 1e [2] 8c 12 [2] 80 18 [2] 97 13 [2] 8c 5d [2] b1 }

  condition:
    any of them
}