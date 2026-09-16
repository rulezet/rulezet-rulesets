rule TTP_XOR_MULT_DOSStub_2ab3 {
  strings:
    $key_2ab3 = { 7e db [2] 0a c3 [2] 4d c1 [2] 0a d0 [2] 44 dc [2] 48 d6 [2] 5f dd [2] 44 93 [2] 79 }

  condition:
    any of them
}