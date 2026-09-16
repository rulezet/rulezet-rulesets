rule TTP_XOR_MULT_DOSStub_7437 {
  strings:
    $key_7437 = { 20 5f [2] 54 47 [2] 13 45 [2] 54 54 [2] 1a 58 [2] 16 52 [2] 01 59 [2] 1a 17 [2] 27 }

  condition:
    any of them
}