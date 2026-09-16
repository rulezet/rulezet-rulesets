rule TTP_XOR_MULT_DOSStub_3e63 {
  strings:
    $key_3e63 = { 6a 0b [2] 1e 13 [2] 59 11 [2] 1e 00 [2] 50 0c [2] 5c 06 [2] 4b 0d [2] 50 43 [2] 6d }

  condition:
    any of them
}