rule TTP_XOR_MULT_DOSStub_65e7 {
  strings:
    $key_65e7 = { 31 8f [2] 45 97 [2] 02 95 [2] 45 84 [2] 0b 88 [2] 07 82 [2] 10 89 [2] 0b c7 [2] 36 }

  condition:
    any of them
}