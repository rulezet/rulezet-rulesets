rule TTP_XOR_MULT_DOSStub_3631 {
  strings:
    $key_3631 = { 62 59 [2] 16 41 [2] 51 43 [2] 16 52 [2] 58 5e [2] 54 54 [2] 43 5f [2] 58 11 [2] 65 }

  condition:
    any of them
}