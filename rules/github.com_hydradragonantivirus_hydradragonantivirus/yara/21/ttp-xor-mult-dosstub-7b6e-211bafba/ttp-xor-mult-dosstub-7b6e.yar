rule TTP_XOR_MULT_DOSStub_7b6e {
  strings:
    $key_7b6e = { 2f 06 [2] 5b 1e [2] 1c 1c [2] 5b 0d [2] 15 01 [2] 19 0b [2] 0e 00 [2] 15 4e [2] 28 }

  condition:
    any of them
}