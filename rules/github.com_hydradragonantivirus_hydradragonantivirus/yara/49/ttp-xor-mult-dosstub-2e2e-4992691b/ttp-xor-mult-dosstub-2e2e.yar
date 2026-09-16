rule TTP_XOR_MULT_DOSStub_2e2e {
  strings:
    $key_2e2e = { 7a 46 [2] 0e 5e [2] 49 5c [2] 0e 4d [2] 40 41 [2] 4c 4b [2] 5b 40 [2] 40 0e [2] 7d }

  condition:
    any of them
}