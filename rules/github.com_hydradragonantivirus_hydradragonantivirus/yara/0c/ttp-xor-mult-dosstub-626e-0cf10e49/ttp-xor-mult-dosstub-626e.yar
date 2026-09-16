rule TTP_XOR_MULT_DOSStub_626e {
  strings:
    $key_626e = { 36 06 [2] 42 1e [2] 05 1c [2] 42 0d [2] 0c 01 [2] 00 0b [2] 17 00 [2] 0c 4e [2] 31 }

  condition:
    any of them
}