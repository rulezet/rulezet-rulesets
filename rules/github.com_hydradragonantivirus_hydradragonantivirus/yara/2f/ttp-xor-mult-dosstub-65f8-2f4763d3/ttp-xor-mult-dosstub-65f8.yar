rule TTP_XOR_MULT_DOSStub_65f8 {
  strings:
    $key_65f8 = { 31 90 [2] 45 88 [2] 02 8a [2] 45 9b [2] 0b 97 [2] 07 9d [2] 10 96 [2] 0b d8 [2] 36 }

  condition:
    any of them
}