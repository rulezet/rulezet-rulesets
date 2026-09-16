rule TTP_XOR_MULT_DOSStub_e3e1 {
  strings:
    $key_e3e1 = { b7 89 [2] c3 91 [2] 84 93 [2] c3 82 [2] 8d 8e [2] 81 84 [2] 96 8f [2] 8d c1 [2] b0 }

  condition:
    any of them
}