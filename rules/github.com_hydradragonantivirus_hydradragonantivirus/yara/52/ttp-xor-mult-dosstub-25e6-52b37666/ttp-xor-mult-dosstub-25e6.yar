rule TTP_XOR_MULT_DOSStub_25e6 {
  strings:
    $key_25e6 = { 71 8e [2] 05 96 [2] 42 94 [2] 05 85 [2] 4b 89 [2] 47 83 [2] 50 88 [2] 4b c6 [2] 76 }

  condition:
    any of them
}