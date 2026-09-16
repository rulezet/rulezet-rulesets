rule TTP_XOR_MULT_DOSStub_5e2e {
  strings:
    $key_5e2e = { 0a 46 [2] 7e 5e [2] 39 5c [2] 7e 4d [2] 30 41 [2] 3c 4b [2] 2b 40 [2] 30 0e [2] 0d }

  condition:
    any of them
}