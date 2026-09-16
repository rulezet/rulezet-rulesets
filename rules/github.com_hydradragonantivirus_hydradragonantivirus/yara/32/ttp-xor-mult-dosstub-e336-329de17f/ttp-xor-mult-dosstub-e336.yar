rule TTP_XOR_MULT_DOSStub_e336 {
  strings:
    $key_e336 = { b7 5e [2] c3 46 [2] 84 44 [2] c3 55 [2] 8d 59 [2] 81 53 [2] 96 58 [2] 8d 16 [2] b0 }

  condition:
    any of them
}