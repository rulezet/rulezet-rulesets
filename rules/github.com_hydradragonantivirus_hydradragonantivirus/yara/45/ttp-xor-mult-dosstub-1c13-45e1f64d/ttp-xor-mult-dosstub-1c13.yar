rule TTP_XOR_MULT_DOSStub_1c13 {
  strings:
    $key_1c13 = { 48 7b [2] 3c 63 [2] 7b 61 [2] 3c 70 [2] 72 7c [2] 7e 76 [2] 69 7d [2] 72 33 [2] 4f }

  condition:
    any of them
}