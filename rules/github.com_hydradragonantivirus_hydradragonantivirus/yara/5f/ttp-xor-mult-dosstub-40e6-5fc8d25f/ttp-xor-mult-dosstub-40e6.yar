rule TTP_XOR_MULT_DOSStub_40e6 {
  strings:
    $key_40e6 = { 14 8e [2] 60 96 [2] 27 94 [2] 60 85 [2] 2e 89 [2] 22 83 [2] 35 88 [2] 2e c6 [2] 13 }

  condition:
    any of them
}