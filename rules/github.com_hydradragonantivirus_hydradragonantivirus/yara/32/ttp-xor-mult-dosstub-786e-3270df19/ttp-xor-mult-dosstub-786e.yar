rule TTP_XOR_MULT_DOSStub_786e {
  strings:
    $key_786e = { 2c 06 [2] 58 1e [2] 1f 1c [2] 58 0d [2] 16 01 [2] 1a 0b [2] 0d 00 [2] 16 4e [2] 2b }

  condition:
    any of them
}