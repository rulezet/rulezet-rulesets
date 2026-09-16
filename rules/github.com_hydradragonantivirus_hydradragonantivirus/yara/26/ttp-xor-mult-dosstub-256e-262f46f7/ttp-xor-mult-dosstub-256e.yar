rule TTP_XOR_MULT_DOSStub_256e {
  strings:
    $key_256e = { 71 06 [2] 05 1e [2] 42 1c [2] 05 0d [2] 4b 01 [2] 47 0b [2] 50 00 [2] 4b 4e [2] 76 }

  condition:
    any of them
}