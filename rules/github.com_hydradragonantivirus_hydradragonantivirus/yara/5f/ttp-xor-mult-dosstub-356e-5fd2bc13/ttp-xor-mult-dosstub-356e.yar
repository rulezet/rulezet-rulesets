rule TTP_XOR_MULT_DOSStub_356e {
  strings:
    $key_356e = { 61 06 [2] 15 1e [2] 52 1c [2] 15 0d [2] 5b 01 [2] 57 0b [2] 40 00 [2] 5b 4e [2] 66 }

  condition:
    any of them
}