rule TTP_XOR_MULT_DOSStub_6137 {
  strings:
    $key_6137 = { 35 5f [2] 41 47 [2] 06 45 [2] 41 54 [2] 0f 58 [2] 03 52 [2] 14 59 [2] 0f 17 [2] 32 }

  condition:
    any of them
}