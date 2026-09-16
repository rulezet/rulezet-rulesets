rule TTP_XOR_MULT_DOSStub_4563 {
  strings:
    $key_4563 = { 11 0b [2] 65 13 [2] 22 11 [2] 65 00 [2] 2b 0c [2] 27 06 [2] 30 0d [2] 2b 43 [2] 16 }

  condition:
    any of them
}