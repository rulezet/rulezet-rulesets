rule TTP_XOR_MULT_DOSStub_4d77 {
  strings:
    $key_4d77 = { 19 1f [2] 6d 07 [2] 2a 05 [2] 6d 14 [2] 23 18 [2] 2f 12 [2] 38 19 [2] 23 57 [2] 1e }

  condition:
    any of them
}