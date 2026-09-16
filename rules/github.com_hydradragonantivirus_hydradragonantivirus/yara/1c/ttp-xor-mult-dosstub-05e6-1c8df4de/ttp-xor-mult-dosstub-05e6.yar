rule TTP_XOR_MULT_DOSStub_05e6 {
  strings:
    $key_05e6 = { 51 8e [2] 25 96 [2] 62 94 [2] 25 85 [2] 6b 89 [2] 67 83 [2] 70 88 [2] 6b c6 [2] 56 }

  condition:
    any of them
}