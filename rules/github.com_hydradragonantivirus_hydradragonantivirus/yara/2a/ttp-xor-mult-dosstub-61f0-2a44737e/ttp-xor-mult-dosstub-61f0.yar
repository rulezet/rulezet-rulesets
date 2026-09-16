rule TTP_XOR_MULT_DOSStub_61f0 {
  strings:
    $key_61f0 = { 35 98 [2] 41 80 [2] 06 82 [2] 41 93 [2] 0f 9f [2] 03 95 [2] 14 9e [2] 0f d0 [2] 32 }

  condition:
    any of them
}