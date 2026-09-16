rule TTP_XOR_MULT_DOSStub_6157 {
  strings:
    $key_6157 = { 35 3f [2] 41 27 [2] 06 25 [2] 41 34 [2] 0f 38 [2] 03 32 [2] 14 39 [2] 0f 77 [2] 32 }

  condition:
    any of them
}