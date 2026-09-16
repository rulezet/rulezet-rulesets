rule TTP_XOR_MULT_DOSStub_186e {
  strings:
    $key_186e = { 4c 06 [2] 38 1e [2] 7f 1c [2] 38 0d [2] 76 01 [2] 7a 0b [2] 6d 00 [2] 76 4e [2] 4b }

  condition:
    any of them
}