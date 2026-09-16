rule TTP_XOR_MULT_DOSStub_4c0e {
  strings:
    $key_4c0e = { 18 66 [2] 6c 7e [2] 2b 7c [2] 6c 6d [2] 22 61 [2] 2e 6b [2] 39 60 [2] 22 2e [2] 1f }

  condition:
    any of them
}