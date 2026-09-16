rule TTP_XOR_MULT_DOSStub_1e63 {
  strings:
    $key_1e63 = { 4a 0b [2] 3e 13 [2] 79 11 [2] 3e 00 [2] 70 0c [2] 7c 06 [2] 6b 0d [2] 70 43 [2] 4d }

  condition:
    any of them
}