rule TTP_XOR_MULT_DOSStub_2400 {
  strings:
    $key_2400 = { 70 68 [2] 04 70 [2] 43 72 [2] 04 63 [2] 4a 6f [2] 46 65 [2] 51 6e [2] 4a 20 [2] 77 }

  condition:
    any of them
}