rule TTP_XOR_MULT_DOSStub_0a63 {
  strings:
    $key_0a63 = { 5e 0b [2] 2a 13 [2] 6d 11 [2] 2a 00 [2] 64 0c [2] 68 06 [2] 7f 0d [2] 64 43 [2] 59 }

  condition:
    any of them
}