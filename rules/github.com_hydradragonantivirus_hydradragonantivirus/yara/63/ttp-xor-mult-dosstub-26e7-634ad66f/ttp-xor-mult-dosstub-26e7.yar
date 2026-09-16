rule TTP_XOR_MULT_DOSStub_26e7 {
  strings:
    $key_26e7 = { 72 8f [2] 06 97 [2] 41 95 [2] 06 84 [2] 48 88 [2] 44 82 [2] 53 89 [2] 48 c7 [2] 75 }

  condition:
    any of them
}