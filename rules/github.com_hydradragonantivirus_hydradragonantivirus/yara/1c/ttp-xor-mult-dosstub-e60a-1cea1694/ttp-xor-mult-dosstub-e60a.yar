rule TTP_XOR_MULT_DOSStub_e60a {
  strings:
    $key_e60a = { b2 62 [2] c6 7a [2] 81 78 [2] c6 69 [2] 88 65 [2] 84 6f [2] 93 64 [2] 88 2a [2] b5 }

  condition:
    any of them
}