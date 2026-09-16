rule TTP_XOR_MULT_DOSStub_5c7e {
  strings:
    $key_5c7e = { 08 16 [2] 7c 0e [2] 3b 0c [2] 7c 1d [2] 32 11 [2] 3e 1b [2] 29 10 [2] 32 5e [2] 0f }

  condition:
    any of them
}