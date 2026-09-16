rule TTP_XOR_MULT_DOSStub_0d77 {
  strings:
    $key_0d77 = { 59 1f [2] 2d 07 [2] 6a 05 [2] 2d 14 [2] 63 18 [2] 6f 12 [2] 78 19 [2] 63 57 [2] 5e }

  condition:
    any of them
}