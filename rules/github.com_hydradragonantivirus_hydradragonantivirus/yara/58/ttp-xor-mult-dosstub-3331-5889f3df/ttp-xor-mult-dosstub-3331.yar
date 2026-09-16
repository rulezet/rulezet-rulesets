rule TTP_XOR_MULT_DOSStub_3331 {
  strings:
    $key_3331 = { 67 59 [2] 13 41 [2] 54 43 [2] 13 52 [2] 5d 5e [2] 51 54 [2] 46 5f [2] 5d 11 [2] 60 }

  condition:
    any of them
}