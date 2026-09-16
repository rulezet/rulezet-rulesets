rule TTP_XOR_MULT_DOSStub_5c2e {
  strings:
    $key_5c2e = { 08 46 [2] 7c 5e [2] 3b 5c [2] 7c 4d [2] 32 41 [2] 3e 4b [2] 29 40 [2] 32 0e [2] 0f }

  condition:
    any of them
}