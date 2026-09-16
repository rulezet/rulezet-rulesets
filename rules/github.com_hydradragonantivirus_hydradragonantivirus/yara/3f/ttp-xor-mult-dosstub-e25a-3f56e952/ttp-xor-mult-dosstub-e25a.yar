rule TTP_XOR_MULT_DOSStub_e25a {
  strings:
    $key_e25a = { b6 32 [2] c2 2a [2] 85 28 [2] c2 39 [2] 8c 35 [2] 80 3f [2] 97 34 [2] 8c 7a [2] b1 }

  condition:
    any of them
}