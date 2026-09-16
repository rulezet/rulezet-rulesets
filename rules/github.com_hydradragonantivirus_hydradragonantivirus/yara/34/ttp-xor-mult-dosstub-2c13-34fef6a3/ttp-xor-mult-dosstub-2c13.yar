rule TTP_XOR_MULT_DOSStub_2c13 {
  strings:
    $key_2c13 = { 78 7b [2] 0c 63 [2] 4b 61 [2] 0c 70 [2] 42 7c [2] 4e 76 [2] 59 7d [2] 42 33 [2] 7f }

  condition:
    any of them
}