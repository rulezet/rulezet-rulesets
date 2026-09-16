rule TTP_XOR_MULT_DOSStub_3617 {
  strings:
    $key_3617 = { 62 7f [2] 16 67 [2] 51 65 [2] 16 74 [2] 58 78 [2] 54 72 [2] 43 79 [2] 58 37 [2] 65 }

  condition:
    any of them
}