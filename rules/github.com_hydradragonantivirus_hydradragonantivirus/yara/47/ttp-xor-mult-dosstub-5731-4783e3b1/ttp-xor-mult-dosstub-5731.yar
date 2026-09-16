rule TTP_XOR_MULT_DOSStub_5731 {
  strings:
    $key_5731 = { 03 59 [2] 77 41 [2] 30 43 [2] 77 52 [2] 39 5e [2] 35 54 [2] 22 5f [2] 39 11 [2] 04 }

  condition:
    any of them
}