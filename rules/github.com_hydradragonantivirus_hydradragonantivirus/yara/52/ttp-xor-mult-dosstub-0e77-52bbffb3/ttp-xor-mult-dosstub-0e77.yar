rule TTP_XOR_MULT_DOSStub_0e77 {
  strings:
    $key_0e77 = { 5a 1f [2] 2e 07 [2] 69 05 [2] 2e 14 [2] 60 18 [2] 6c 12 [2] 7b 19 [2] 60 57 [2] 5d }

  condition:
    any of them
}