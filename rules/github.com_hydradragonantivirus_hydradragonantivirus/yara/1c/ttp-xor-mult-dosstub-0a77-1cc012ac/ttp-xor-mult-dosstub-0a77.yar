rule TTP_XOR_MULT_DOSStub_0a77 {
  strings:
    $key_0a77 = { 5e 1f [2] 2a 07 [2] 6d 05 [2] 2a 14 [2] 64 18 [2] 68 12 [2] 7f 19 [2] 64 57 [2] 59 }

  condition:
    any of them
}