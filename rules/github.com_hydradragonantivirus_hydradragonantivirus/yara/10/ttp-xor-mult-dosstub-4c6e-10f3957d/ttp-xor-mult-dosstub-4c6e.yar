rule TTP_XOR_MULT_DOSStub_4c6e {
  strings:
    $key_4c6e = { 18 06 [2] 6c 1e [2] 2b 1c [2] 6c 0d [2] 22 01 [2] 2e 0b [2] 39 00 [2] 22 4e [2] 1f }

  condition:
    any of them
}