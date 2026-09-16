rule TTP_XOR_MULT_DOSStub_4c13 {
  strings:
    $key_4c13 = { 18 7b [2] 6c 63 [2] 2b 61 [2] 6c 70 [2] 22 7c [2] 2e 76 [2] 39 7d [2] 22 33 [2] 1f }

  condition:
    any of them
}