rule TTP_XOR_MULT_DOSStub_1726 {
  strings:
    $key_1726 = { 43 4e [2] 37 56 [2] 70 54 [2] 37 45 [2] 79 49 [2] 75 43 [2] 62 48 [2] 79 06 [2] 44 }

  condition:
    any of them
}