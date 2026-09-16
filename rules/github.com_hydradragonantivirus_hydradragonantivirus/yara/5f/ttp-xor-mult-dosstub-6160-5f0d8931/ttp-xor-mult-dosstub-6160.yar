rule TTP_XOR_MULT_DOSStub_6160 {
  strings:
    $key_6160 = { 35 08 [2] 41 10 [2] 06 12 [2] 41 03 [2] 0f 0f [2] 03 05 [2] 14 0e [2] 0f 40 [2] 32 }

  condition:
    any of them
}