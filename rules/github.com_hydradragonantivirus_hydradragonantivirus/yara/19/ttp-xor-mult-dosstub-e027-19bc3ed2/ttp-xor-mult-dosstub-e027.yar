rule TTP_XOR_MULT_DOSStub_e027 {
  strings:
    $key_e027 = { b4 4f [2] c0 57 [2] 87 55 [2] c0 44 [2] 8e 48 [2] 82 42 [2] 95 49 [2] 8e 07 [2] b3 }

  condition:
    any of them
}