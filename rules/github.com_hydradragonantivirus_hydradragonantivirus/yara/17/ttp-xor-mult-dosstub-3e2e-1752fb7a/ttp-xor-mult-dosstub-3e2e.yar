rule TTP_XOR_MULT_DOSStub_3e2e {
  strings:
    $key_3e2e = { 6a 46 [2] 1e 5e [2] 59 5c [2] 1e 4d [2] 50 41 [2] 5c 4b [2] 4b 40 [2] 50 0e [2] 6d }

  condition:
    any of them
}