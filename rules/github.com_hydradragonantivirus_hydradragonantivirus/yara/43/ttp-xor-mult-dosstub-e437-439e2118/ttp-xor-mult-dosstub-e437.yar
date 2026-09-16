rule TTP_XOR_MULT_DOSStub_e437 {
  strings:
    $key_e437 = { b0 5f [2] c4 47 [2] 83 45 [2] c4 54 [2] 8a 58 [2] 86 52 [2] 91 59 [2] 8a 17 [2] b7 }

  condition:
    any of them
}