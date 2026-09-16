rule TTP_XOR_MULT_DOSStub_e441 {
  strings:
    $key_e441 = { b0 29 [2] c4 31 [2] 83 33 [2] c4 22 [2] 8a 2e [2] 86 24 [2] 91 2f [2] 8a 61 [2] b7 }

  condition:
    any of them
}