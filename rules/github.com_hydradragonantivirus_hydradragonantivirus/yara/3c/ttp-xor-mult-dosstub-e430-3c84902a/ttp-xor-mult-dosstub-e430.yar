rule TTP_XOR_MULT_DOSStub_e430 {
  strings:
    $key_e430 = { b0 58 [2] c4 40 [2] 83 42 [2] c4 53 [2] 8a 5f [2] 86 55 [2] 91 5e [2] 8a 10 [2] b7 }

  condition:
    any of them
}