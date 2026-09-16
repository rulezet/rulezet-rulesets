rule TTP_XOR_MULT_DOSStub_c030 {
  strings:
    $key_c030 = { 94 58 [2] e0 40 [2] a7 42 [2] e0 53 [2] ae 5f [2] a2 55 [2] b5 5e [2] ae 10 [2] 93 }

  condition:
    any of them
}