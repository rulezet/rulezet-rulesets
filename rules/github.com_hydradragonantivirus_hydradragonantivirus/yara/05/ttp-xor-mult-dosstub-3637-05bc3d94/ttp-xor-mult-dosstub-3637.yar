rule TTP_XOR_MULT_DOSStub_3637 {
  strings:
    $key_3637 = { 62 5f [2] 16 47 [2] 51 45 [2] 16 54 [2] 58 58 [2] 54 52 [2] 43 59 [2] 58 17 [2] 65 }

  condition:
    any of them
}