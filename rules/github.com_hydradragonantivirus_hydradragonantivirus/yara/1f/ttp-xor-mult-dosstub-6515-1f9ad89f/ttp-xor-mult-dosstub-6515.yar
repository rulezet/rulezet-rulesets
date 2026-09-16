rule TTP_XOR_MULT_DOSStub_6515 {
  strings:
    $key_6515 = { 31 7d [2] 45 65 [2] 02 67 [2] 45 76 [2] 0b 7a [2] 07 70 [2] 10 7b [2] 0b 35 [2] 36 }

  condition:
    any of them
}