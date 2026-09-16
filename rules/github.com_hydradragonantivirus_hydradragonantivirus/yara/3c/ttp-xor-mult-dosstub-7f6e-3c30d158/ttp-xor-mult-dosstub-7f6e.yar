rule TTP_XOR_MULT_DOSStub_7f6e {
  strings:
    $key_7f6e = { 2b 06 [2] 5f 1e [2] 18 1c [2] 5f 0d [2] 11 01 [2] 1d 0b [2] 0a 00 [2] 11 4e [2] 2c }

  condition:
    any of them
}