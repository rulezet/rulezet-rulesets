rule TTP_XOR_MULT_DOSStub_7a6e {
  strings:
    $key_7a6e = { 2e 06 [2] 5a 1e [2] 1d 1c [2] 5a 0d [2] 14 01 [2] 18 0b [2] 0f 00 [2] 14 4e [2] 29 }

  condition:
    any of them
}