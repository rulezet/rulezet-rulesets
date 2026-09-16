rule TTP_XOR_MULT_DOSStub_7277 {
  strings:
    $key_7277 = { 26 1f [2] 52 07 [2] 15 05 [2] 52 14 [2] 1c 18 [2] 10 12 [2] 07 19 [2] 1c 57 [2] 21 }

  condition:
    any of them
}