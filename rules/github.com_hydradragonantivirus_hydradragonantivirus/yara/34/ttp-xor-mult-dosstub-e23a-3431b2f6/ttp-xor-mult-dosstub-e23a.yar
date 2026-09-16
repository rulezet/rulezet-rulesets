rule TTP_XOR_MULT_DOSStub_e23a {
  strings:
    $key_e23a = { b6 52 [2] c2 4a [2] 85 48 [2] c2 59 [2] 8c 55 [2] 80 5f [2] 97 54 [2] 8c 1a [2] b1 }

  condition:
    any of them
}