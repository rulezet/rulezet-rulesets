rule TTP_XOR_MULT_DOSStub_c023 {
  strings:
    $key_c023 = { 94 4b [2] e0 53 [2] a7 51 [2] e0 40 [2] ae 4c [2] a2 46 [2] b5 4d [2] ae 03 [2] 93 }

  condition:
    any of them
}