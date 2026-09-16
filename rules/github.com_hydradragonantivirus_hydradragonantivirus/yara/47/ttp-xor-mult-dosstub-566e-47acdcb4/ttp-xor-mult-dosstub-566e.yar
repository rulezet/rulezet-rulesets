rule TTP_XOR_MULT_DOSStub_566e {
  strings:
    $key_566e = { 02 06 [2] 76 1e [2] 31 1c [2] 76 0d [2] 38 01 [2] 34 0b [2] 23 00 [2] 38 4e [2] 05 }

  condition:
    any of them
}