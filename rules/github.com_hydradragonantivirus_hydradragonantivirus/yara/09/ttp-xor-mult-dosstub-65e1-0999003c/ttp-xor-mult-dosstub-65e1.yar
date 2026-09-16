rule TTP_XOR_MULT_DOSStub_65e1 {
  strings:
    $key_65e1 = { 31 89 [2] 45 91 [2] 02 93 [2] 45 82 [2] 0b 8e [2] 07 84 [2] 10 8f [2] 0b c1 [2] 36 }

  condition:
    any of them
}