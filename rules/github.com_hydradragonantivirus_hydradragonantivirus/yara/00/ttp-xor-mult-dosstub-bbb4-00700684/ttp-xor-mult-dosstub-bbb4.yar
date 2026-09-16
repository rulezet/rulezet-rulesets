rule TTP_XOR_MULT_DOSStub_bbb4 {
  strings:
    $key_bbb4 = { ef dc [2] 9b c4 [2] dc c6 [2] 9b d7 [2] d5 db [2] d9 d1 [2] ce da [2] d5 94 [2] e8 }

  condition:
    any of them
}