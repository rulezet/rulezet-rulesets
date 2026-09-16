rule TTP_XOR_MULT_DOSStub_7131 {
  strings:
    $key_7131 = { 25 59 [2] 51 41 [2] 16 43 [2] 51 52 [2] 1f 5e [2] 13 54 [2] 04 5f [2] 1f 11 [2] 22 }

  condition:
    any of them
}