rule TTP_XOR_MULT_DOSStub_6c13 {
  strings:
    $key_6c13 = { 38 7b [2] 4c 63 [2] 0b 61 [2] 4c 70 [2] 02 7c [2] 0e 76 [2] 19 7d [2] 02 33 [2] 3f }

  condition:
    any of them
}