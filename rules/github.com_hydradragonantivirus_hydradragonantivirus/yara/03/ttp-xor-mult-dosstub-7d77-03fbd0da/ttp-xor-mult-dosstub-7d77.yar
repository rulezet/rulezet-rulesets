rule TTP_XOR_MULT_DOSStub_7d77 {
  strings:
    $key_7d77 = { 29 1f [2] 5d 07 [2] 1a 05 [2] 5d 14 [2] 13 18 [2] 1f 12 [2] 08 19 [2] 13 57 [2] 2e }

  condition:
    any of them
}