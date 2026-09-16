rule TTP_XOR_MULT_DOSStub_5c0e {
  strings:
    $key_5c0e = { 08 66 [2] 7c 7e [2] 3b 7c [2] 7c 6d [2] 32 61 [2] 3e 6b [2] 29 60 [2] 32 2e [2] 0f }

  condition:
    any of them
}