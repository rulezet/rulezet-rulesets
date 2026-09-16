rule TTP_XOR_MULT_DOSStub_e249 {
  strings:
    $key_e249 = { b6 21 [2] c2 39 [2] 85 3b [2] c2 2a [2] 8c 26 [2] 80 2c [2] 97 27 [2] 8c 69 [2] b1 }

  condition:
    any of them
}