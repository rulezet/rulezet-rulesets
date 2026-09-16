rule TTP_XOR_MULT_DOSStub_3c77 {
  strings:
    $key_3c77 = { 68 1f [2] 1c 07 [2] 5b 05 [2] 1c 14 [2] 52 18 [2] 5e 12 [2] 49 19 [2] 52 57 [2] 6f }

  condition:
    any of them
}