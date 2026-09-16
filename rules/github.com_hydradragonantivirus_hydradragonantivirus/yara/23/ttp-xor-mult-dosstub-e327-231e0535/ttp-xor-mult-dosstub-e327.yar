rule TTP_XOR_MULT_DOSStub_e327 {
  strings:
    $key_e327 = { b7 4f [2] c3 57 [2] 84 55 [2] c3 44 [2] 8d 48 [2] 81 42 [2] 96 49 [2] 8d 07 [2] b0 }

  condition:
    any of them
}