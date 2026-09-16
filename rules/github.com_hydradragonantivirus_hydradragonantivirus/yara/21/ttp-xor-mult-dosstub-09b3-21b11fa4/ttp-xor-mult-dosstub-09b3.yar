rule TTP_XOR_MULT_DOSStub_09b3 {
  strings:
    $key_09b3 = { 5d db [2] 29 c3 [2] 6e c1 [2] 29 d0 [2] 67 dc [2] 6b d6 [2] 7c dd [2] 67 93 [2] 5a }

  condition:
    any of them
}