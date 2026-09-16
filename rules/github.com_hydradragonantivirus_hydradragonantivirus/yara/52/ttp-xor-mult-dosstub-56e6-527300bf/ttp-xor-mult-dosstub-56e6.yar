rule TTP_XOR_MULT_DOSStub_56e6 {
  strings:
    $key_56e6 = { 02 8e [2] 76 96 [2] 31 94 [2] 76 85 [2] 38 89 [2] 34 83 [2] 23 88 [2] 38 c6 [2] 05 }

  condition:
    any of them
}