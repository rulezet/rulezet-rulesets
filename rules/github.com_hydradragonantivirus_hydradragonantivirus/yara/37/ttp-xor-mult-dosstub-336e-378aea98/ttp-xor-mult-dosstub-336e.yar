rule TTP_XOR_MULT_DOSStub_336e {
  strings:
    $key_336e = { 67 06 [2] 13 1e [2] 54 1c [2] 13 0d [2] 5d 01 [2] 51 0b [2] 46 00 [2] 5d 4e [2] 60 }

  condition:
    any of them
}