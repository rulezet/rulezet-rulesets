rule TTP_XOR_MULT_DOSStub_1e6e {
  strings:
    $key_1e6e = { 4a 06 [2] 3e 1e [2] 79 1c [2] 3e 0d [2] 70 01 [2] 7c 0b [2] 6b 00 [2] 70 4e [2] 4d }

  condition:
    any of them
}