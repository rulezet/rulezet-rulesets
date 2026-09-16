rule TTP_XOR_MULT_DOSStub_7d6e {
  strings:
    $key_7d6e = { 29 06 [2] 5d 1e [2] 1a 1c [2] 5d 0d [2] 13 01 [2] 1f 0b [2] 08 00 [2] 13 4e [2] 2e }

  condition:
    any of them
}