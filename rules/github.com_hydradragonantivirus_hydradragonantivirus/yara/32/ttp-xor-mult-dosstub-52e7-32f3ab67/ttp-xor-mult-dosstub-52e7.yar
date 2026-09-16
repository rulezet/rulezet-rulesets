rule TTP_XOR_MULT_DOSStub_52e7 {
  strings:
    $key_52e7 = { 06 8f [2] 72 97 [2] 35 95 [2] 72 84 [2] 3c 88 [2] 30 82 [2] 27 89 [2] 3c c7 [2] 01 }

  condition:
    any of them
}