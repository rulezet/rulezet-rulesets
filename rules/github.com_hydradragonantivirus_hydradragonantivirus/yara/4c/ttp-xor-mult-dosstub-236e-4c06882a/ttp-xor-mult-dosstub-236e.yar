rule TTP_XOR_MULT_DOSStub_236e {
  strings:
    $key_236e = { 77 06 [2] 03 1e [2] 44 1c [2] 03 0d [2] 4d 01 [2] 41 0b [2] 56 00 [2] 4d 4e [2] 70 }

  condition:
    any of them
}