rule TTP_XOR_MULT_DOSStub_6150 {
  strings:
    $key_6150 = { 35 38 [2] 41 20 [2] 06 22 [2] 41 33 [2] 0f 3f [2] 03 35 [2] 14 3e [2] 0f 70 [2] 32 }

  condition:
    any of them
}