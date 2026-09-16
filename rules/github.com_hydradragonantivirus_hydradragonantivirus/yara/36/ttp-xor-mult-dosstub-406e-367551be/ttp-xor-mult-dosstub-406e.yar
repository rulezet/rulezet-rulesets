rule TTP_XOR_MULT_DOSStub_406e {
  strings:
    $key_406e = { 14 06 [2] 60 1e [2] 27 1c [2] 60 0d [2] 2e 01 [2] 22 0b [2] 35 00 [2] 2e 4e [2] 13 }

  condition:
    any of them
}