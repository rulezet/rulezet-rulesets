rule TTP_XOR_MULT_DOSStub_bbb3 {
  strings:
    $key_bbb3 = { ef db [2] 9b c3 [2] dc c1 [2] 9b d0 [2] d5 dc [2] d9 d6 [2] ce dd [2] d5 93 [2] e8 }

  condition:
    any of them
}