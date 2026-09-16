rule TTP_XOR_MULT_DOSStub_6151 {
  strings:
    $key_6151 = { 35 39 [2] 41 21 [2] 06 23 [2] 41 32 [2] 0f 3e [2] 03 34 [2] 14 3f [2] 0f 71 [2] 32 }

  condition:
    any of them
}