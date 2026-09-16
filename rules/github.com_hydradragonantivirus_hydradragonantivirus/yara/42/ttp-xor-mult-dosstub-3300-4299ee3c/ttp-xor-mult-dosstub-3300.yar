rule TTP_XOR_MULT_DOSStub_3300 {
  strings:
    $key_3300 = { 67 68 [2] 13 70 [2] 54 72 [2] 13 63 [2] 5d 6f [2] 51 65 [2] 46 6e [2] 5d 20 [2] 60 }

  condition:
    any of them
}