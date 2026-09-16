rule TTP_XOR_MULT_DOSStub_0e6e {
  strings:
    $key_0e6e = { 5a 06 [2] 2e 1e [2] 69 1c [2] 2e 0d [2] 60 01 [2] 6c 0b [2] 7b 00 [2] 60 4e [2] 5d }

  condition:
    any of them
}