rule TTP_XOR_MULT_DOSStub_4c63 {
  strings:
    $key_4c63 = { 18 0b [2] 6c 13 [2] 2b 11 [2] 6c 00 [2] 22 0c [2] 2e 06 [2] 39 0d [2] 22 43 [2] 1f }

  condition:
    any of them
}