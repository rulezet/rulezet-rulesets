rule TTP_XOR_MULT_DOSStub_266e {
  strings:
    $key_266e = { 72 06 [2] 06 1e [2] 41 1c [2] 06 0d [2] 48 01 [2] 44 0b [2] 53 00 [2] 48 4e [2] 75 }

  condition:
    any of them
}