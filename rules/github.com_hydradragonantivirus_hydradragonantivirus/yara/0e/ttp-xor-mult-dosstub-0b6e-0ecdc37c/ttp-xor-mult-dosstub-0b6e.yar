rule TTP_XOR_MULT_DOSStub_0b6e {
  strings:
    $key_0b6e = { 5f 06 [2] 2b 1e [2] 6c 1c [2] 2b 0d [2] 65 01 [2] 69 0b [2] 7e 00 [2] 65 4e [2] 58 }

  condition:
    any of them
}