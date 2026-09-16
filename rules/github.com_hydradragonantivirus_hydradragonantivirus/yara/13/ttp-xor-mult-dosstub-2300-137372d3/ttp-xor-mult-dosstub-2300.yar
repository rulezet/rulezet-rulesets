rule TTP_XOR_MULT_DOSStub_2300 {
  strings:
    $key_2300 = { 77 68 [2] 03 70 [2] 44 72 [2] 03 63 [2] 4d 6f [2] 41 65 [2] 56 6e [2] 4d 20 [2] 70 }

  condition:
    any of them
}