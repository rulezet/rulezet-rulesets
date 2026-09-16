rule TTP_XOR_MULT_DOSStub_c037 {
  strings:
    $key_c037 = { 94 5f [2] e0 47 [2] a7 45 [2] e0 54 [2] ae 58 [2] a2 52 [2] b5 59 [2] ae 17 [2] 93 }

  condition:
    any of them
}