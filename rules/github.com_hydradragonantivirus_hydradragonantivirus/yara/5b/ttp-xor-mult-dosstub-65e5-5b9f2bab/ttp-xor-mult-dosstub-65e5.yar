rule TTP_XOR_MULT_DOSStub_65e5 {
  strings:
    $key_65e5 = { 31 8d [2] 45 95 [2] 02 97 [2] 45 86 [2] 0b 8a [2] 07 80 [2] 10 8b [2] 0b c5 [2] 36 }

  condition:
    any of them
}