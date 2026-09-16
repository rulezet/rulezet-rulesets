rule TTP_XOR_MULT_DOSStub_5e3e {
  strings:
    $key_5e3e = { 0a 56 [2] 7e 4e [2] 39 4c [2] 7e 5d [2] 30 51 [2] 3c 5b [2] 2b 50 [2] 30 1e [2] 0d }

  condition:
    any of them
}