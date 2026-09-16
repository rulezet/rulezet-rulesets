rule TTP_XOR_MULT_DOSStub_c021 {
  strings:
    $key_c021 = { 94 49 [2] e0 51 [2] a7 53 [2] e0 42 [2] ae 4e [2] a2 44 [2] b5 4f [2] ae 01 [2] 93 }

  condition:
    any of them
}