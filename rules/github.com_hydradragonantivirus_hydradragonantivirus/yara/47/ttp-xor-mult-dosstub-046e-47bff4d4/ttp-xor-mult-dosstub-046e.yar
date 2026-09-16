rule TTP_XOR_MULT_DOSStub_046e {
  strings:
    $key_046e = { 50 06 [2] 24 1e [2] 63 1c [2] 24 0d [2] 6a 01 [2] 66 0b [2] 71 00 [2] 6a 4e [2] 57 }

  condition:
    any of them
}