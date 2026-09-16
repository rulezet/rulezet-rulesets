rule TTP_XOR_MULT_DOSStub_e421 {
  strings:
    $key_e421 = { b0 49 [2] c4 51 [2] 83 53 [2] c4 42 [2] 8a 4e [2] 86 44 [2] 91 4f [2] 8a 01 [2] b7 }

  condition:
    any of them
}