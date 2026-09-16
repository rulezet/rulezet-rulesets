rule TTP_XOR_MULT_DOSStub_0277 {
  strings:
    $key_0277 = { 56 1f [2] 22 07 [2] 65 05 [2] 22 14 [2] 6c 18 [2] 60 12 [2] 77 19 [2] 6c 57 [2] 51 }

  condition:
    any of them
}