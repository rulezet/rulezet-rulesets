rule TTP_XOR_MULT_DOSStub_206e {
  strings:
    $key_206e = { 74 06 [2] 00 1e [2] 47 1c [2] 00 0d [2] 4e 01 [2] 42 0b [2] 55 00 [2] 4e 4e [2] 73 }

  condition:
    any of them
}