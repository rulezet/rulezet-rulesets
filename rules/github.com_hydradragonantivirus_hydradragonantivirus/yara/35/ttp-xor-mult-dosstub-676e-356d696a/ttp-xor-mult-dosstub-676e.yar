rule TTP_XOR_MULT_DOSStub_676e {
  strings:
    $key_676e = { 33 06 [2] 47 1e [2] 00 1c [2] 47 0d [2] 09 01 [2] 05 0b [2] 12 00 [2] 09 4e [2] 34 }

  condition:
    any of them
}