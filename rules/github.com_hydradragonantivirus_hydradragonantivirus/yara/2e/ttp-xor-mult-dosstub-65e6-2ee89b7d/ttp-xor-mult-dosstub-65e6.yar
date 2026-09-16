rule TTP_XOR_MULT_DOSStub_65e6 {
  strings:
    $key_65e6 = { 31 8e [2] 45 96 [2] 02 94 [2] 45 85 [2] 0b 89 [2] 07 83 [2] 10 88 [2] 0b c6 [2] 36 }

  condition:
    any of them
}