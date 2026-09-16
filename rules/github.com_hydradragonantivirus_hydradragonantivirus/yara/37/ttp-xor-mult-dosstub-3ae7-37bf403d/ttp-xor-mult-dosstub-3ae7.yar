rule TTP_XOR_MULT_DOSStub_3ae7 {
  strings:
    $key_3ae7 = { 6e 8f [2] 1a 97 [2] 5d 95 [2] 1a 84 [2] 54 88 [2] 58 82 [2] 4f 89 [2] 54 c7 [2] 69 }

  condition:
    any of them
}