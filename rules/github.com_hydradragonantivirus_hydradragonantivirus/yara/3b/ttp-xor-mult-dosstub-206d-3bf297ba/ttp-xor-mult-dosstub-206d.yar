rule TTP_XOR_MULT_DOSStub_206d {
  strings:
    $key_206d = { 74 05 [2] 00 1d [2] 47 1f [2] 00 0e [2] 4e 02 [2] 42 08 [2] 55 03 [2] 4e 4d [2] 73 }

  condition:
    any of them
}