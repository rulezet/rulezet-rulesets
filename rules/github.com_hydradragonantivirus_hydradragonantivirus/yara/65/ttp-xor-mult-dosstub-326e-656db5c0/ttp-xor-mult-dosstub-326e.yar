rule TTP_XOR_MULT_DOSStub_326e {
  strings:
    $key_326e = { 66 06 [2] 12 1e [2] 55 1c [2] 12 0d [2] 5c 01 [2] 50 0b [2] 47 00 [2] 5c 4e [2] 61 }

  condition:
    any of them
}