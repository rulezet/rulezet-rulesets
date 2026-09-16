rule TTP_XOR_MULT_DOSStub_e232 {
  strings:
    $key_e232 = { b6 5a [2] c2 42 [2] 85 40 [2] c2 51 [2] 8c 5d [2] 80 57 [2] 97 5c [2] 8c 12 [2] b1 }

  condition:
    any of them
}