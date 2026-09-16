rule TTP_XOR_MULT_DOSStub_3870 {
  strings:
    $key_3870 = { 6c 18 [2] 18 00 [2] 5f 02 [2] 18 13 [2] 56 1f [2] 5a 15 [2] 4d 1e [2] 56 50 [2] 6b }

  condition:
    any of them
}