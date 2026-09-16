rule TTP_XOR_MULT_DOSStub_e20a {
  strings:
    $key_e20a = { b6 62 [2] c2 7a [2] 85 78 [2] c2 69 [2] 8c 65 [2] 80 6f [2] 97 64 [2] 8c 2a [2] b1 }

  condition:
    any of them
}