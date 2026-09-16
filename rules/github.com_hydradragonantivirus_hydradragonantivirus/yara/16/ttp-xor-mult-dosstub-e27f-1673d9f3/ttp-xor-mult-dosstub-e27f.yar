rule TTP_XOR_MULT_DOSStub_e27f {
  strings:
    $key_e27f = { b6 17 [2] c2 0f [2] 85 0d [2] c2 1c [2] 8c 10 [2] 80 1a [2] 97 11 [2] 8c 5f [2] b1 }

  condition:
    any of them
}