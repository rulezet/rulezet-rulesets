rule TTP_XOR_MULT_DOSStub_61f1 {
  strings:
    $key_61f1 = { 35 99 [2] 41 81 [2] 06 83 [2] 41 92 [2] 0f 9e [2] 03 94 [2] 14 9f [2] 0f d1 [2] 32 }

  condition:
    any of them
}