rule TTP_XOR_MULT_DOSStub_2e6e {
  strings:
    $key_2e6e = { 7a 06 [2] 0e 1e [2] 49 1c [2] 0e 0d [2] 40 01 [2] 4c 0b [2] 5b 00 [2] 40 4e [2] 7d }

  condition:
    any of them
}