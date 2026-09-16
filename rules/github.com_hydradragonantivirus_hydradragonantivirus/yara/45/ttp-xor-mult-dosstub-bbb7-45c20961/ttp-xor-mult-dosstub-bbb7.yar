rule TTP_XOR_MULT_DOSStub_bbb7 {
  strings:
    $key_bbb7 = { ef df [2] 9b c7 [2] dc c5 [2] 9b d4 [2] d5 d8 [2] d9 d2 [2] ce d9 [2] d5 97 [2] e8 }

  condition:
    any of them
}