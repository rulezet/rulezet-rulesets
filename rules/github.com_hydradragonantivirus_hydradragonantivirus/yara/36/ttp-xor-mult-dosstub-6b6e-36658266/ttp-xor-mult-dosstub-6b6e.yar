rule TTP_XOR_MULT_DOSStub_6b6e {
  strings:
    $key_6b6e = { 3f 06 [2] 4b 1e [2] 0c 1c [2] 4b 0d [2] 05 01 [2] 09 0b [2] 1e 00 [2] 05 4e [2] 38 }

  condition:
    any of them
}