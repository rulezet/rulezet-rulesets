rule TTP_XOR_MULT_DOSStub_5e6e {
  strings:
    $key_5e6e = { 0a 06 [2] 7e 1e [2] 39 1c [2] 7e 0d [2] 30 01 [2] 3c 0b [2] 2b 00 [2] 30 4e [2] 0d }

  condition:
    any of them
}