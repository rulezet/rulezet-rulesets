rule TTP_XOR_MULT_DOSStub_036e {
  strings:
    $key_036e = { 57 06 [2] 23 1e [2] 64 1c [2] 23 0d [2] 6d 01 [2] 61 0b [2] 76 00 [2] 6d 4e [2] 50 }

  condition:
    any of them
}