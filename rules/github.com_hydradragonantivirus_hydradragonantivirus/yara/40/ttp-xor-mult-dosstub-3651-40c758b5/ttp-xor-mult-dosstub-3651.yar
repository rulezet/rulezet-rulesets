rule TTP_XOR_MULT_DOSStub_3651 {
  strings:
    $key_3651 = { 62 39 [2] 16 21 [2] 51 23 [2] 16 32 [2] 58 3e [2] 54 34 [2] 43 3f [2] 58 71 [2] 65 }

  condition:
    any of them
}