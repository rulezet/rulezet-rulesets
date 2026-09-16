rule TTP_XOR_MULT_DOSStub_6e77 {
  strings:
    $key_6e77 = { 3a 1f [2] 4e 07 [2] 09 05 [2] 4e 14 [2] 00 18 [2] 0c 12 [2] 1b 19 [2] 00 57 [2] 3d }

  condition:
    any of them
}