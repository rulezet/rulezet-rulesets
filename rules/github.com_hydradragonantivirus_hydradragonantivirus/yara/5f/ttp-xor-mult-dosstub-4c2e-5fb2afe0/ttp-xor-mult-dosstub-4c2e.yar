rule TTP_XOR_MULT_DOSStub_4c2e {
  strings:
    $key_4c2e = { 18 46 [2] 6c 5e [2] 2b 5c [2] 6c 4d [2] 22 41 [2] 2e 4b [2] 39 40 [2] 22 0e [2] 1f }

  condition:
    any of them
}