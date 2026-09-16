rule TTP_XOR_MULT_DOSStub_6c15 {
  strings:
    $key_6c15 = { 38 7d [2] 4c 65 [2] 0b 67 [2] 4c 76 [2] 02 7a [2] 0e 70 [2] 19 7b [2] 02 35 [2] 3f }

  condition:
    any of them
}