rule TTP_XOR_MULT_DOSStub_506e {
  strings:
    $key_506e = { 04 06 [2] 70 1e [2] 37 1c [2] 70 0d [2] 3e 01 [2] 32 0b [2] 25 00 [2] 3e 4e [2] 03 }

  condition:
    any of them
}