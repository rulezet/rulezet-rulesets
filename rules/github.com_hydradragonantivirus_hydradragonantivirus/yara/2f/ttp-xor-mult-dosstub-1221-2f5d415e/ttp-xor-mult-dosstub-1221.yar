rule TTP_XOR_MULT_DOSStub_1221 {
  strings:
    $key_1221 = { 46 49 [2] 32 51 [2] 75 53 [2] 32 42 [2] 7c 4e [2] 70 44 [2] 67 4f [2] 7c 01 [2] 41 }

  condition:
    any of them
}