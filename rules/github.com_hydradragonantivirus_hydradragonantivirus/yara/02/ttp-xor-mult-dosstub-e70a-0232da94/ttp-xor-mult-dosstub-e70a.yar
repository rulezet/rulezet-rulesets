rule TTP_XOR_MULT_DOSStub_e70a {
  strings:
    $key_e70a = { b3 62 [2] c7 7a [2] 80 78 [2] c7 69 [2] 89 65 [2] 85 6f [2] 92 64 [2] 89 2a [2] b4 }

  condition:
    any of them
}