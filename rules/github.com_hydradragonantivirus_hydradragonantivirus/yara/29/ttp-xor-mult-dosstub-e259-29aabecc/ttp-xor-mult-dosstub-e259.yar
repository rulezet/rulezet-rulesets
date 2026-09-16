rule TTP_XOR_MULT_DOSStub_e259 {
  strings:
    $key_e259 = { b6 31 [2] c2 29 [2] 85 2b [2] c2 3a [2] 8c 36 [2] 80 3c [2] 97 37 [2] 8c 79 [2] b1 }

  condition:
    any of them
}