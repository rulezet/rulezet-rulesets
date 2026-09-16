rule TTP_XOR_MULT_DOSStub_1e77 {
  strings:
    $key_1e77 = { 4a 1f [2] 3e 07 [2] 79 05 [2] 3e 14 [2] 70 18 [2] 7c 12 [2] 6b 19 [2] 70 57 [2] 4d }

  condition:
    any of them
}