rule TTP_XOR_MULT_DOSStub_666e {
  strings:
    $key_666e = { 32 06 [2] 46 1e [2] 01 1c [2] 46 0d [2] 08 01 [2] 04 0b [2] 13 00 [2] 08 4e [2] 35 }

  condition:
    any of them
}