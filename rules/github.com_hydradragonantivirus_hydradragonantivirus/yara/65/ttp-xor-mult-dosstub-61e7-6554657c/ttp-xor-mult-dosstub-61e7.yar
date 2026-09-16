rule TTP_XOR_MULT_DOSStub_61e7 {
  strings:
    $key_61e7 = { 35 8f [2] 41 97 [2] 06 95 [2] 41 84 [2] 0f 88 [2] 03 82 [2] 14 89 [2] 0f c7 [2] 32 }

  condition:
    any of them
}