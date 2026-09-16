rule TTP_XOR_MULT_DOSStub_7621 {
  strings:
    $key_7621 = { 22 49 [2] 56 51 [2] 11 53 [2] 56 42 [2] 18 4e [2] 14 44 [2] 03 4f [2] 18 01 [2] 25 }

  condition:
    any of them
}