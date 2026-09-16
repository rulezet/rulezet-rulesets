rule TTP_XOR_MULT_DOSStub_65f6 {
  strings:
    $key_65f6 = { 31 9e [2] 45 86 [2] 02 84 [2] 45 95 [2] 0b 99 [2] 07 93 [2] 10 98 [2] 0b d6 [2] 36 }

  condition:
    any of them
}