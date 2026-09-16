rule TTP_XOR_MULT_DOSStub_c036 {
  strings:
    $key_c036 = { 94 5e [2] e0 46 [2] a7 44 [2] e0 55 [2] ae 59 [2] a2 53 [2] b5 58 [2] ae 16 [2] 93 }

  condition:
    any of them
}