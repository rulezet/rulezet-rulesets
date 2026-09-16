rule TTP_XOR_MULT_DOSStub_e426 {
  strings:
    $key_e426 = { b0 4e [2] c4 56 [2] 83 54 [2] c4 45 [2] 8a 49 [2] 86 43 [2] 91 48 [2] 8a 06 [2] b7 }

  condition:
    any of them
}