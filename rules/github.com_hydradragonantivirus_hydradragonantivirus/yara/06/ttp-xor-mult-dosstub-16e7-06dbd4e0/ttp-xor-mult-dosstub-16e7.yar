rule TTP_XOR_MULT_DOSStub_16e7 {
  strings:
    $key_16e7 = { 42 8f [2] 36 97 [2] 71 95 [2] 36 84 [2] 78 88 [2] 74 82 [2] 63 89 [2] 78 c7 [2] 45 }

  condition:
    any of them
}