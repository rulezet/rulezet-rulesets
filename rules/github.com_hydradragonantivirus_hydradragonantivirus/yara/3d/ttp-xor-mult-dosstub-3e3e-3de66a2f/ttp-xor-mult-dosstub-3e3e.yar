rule TTP_XOR_MULT_DOSStub_3e3e {
  strings:
    $key_3e3e = { 6a 56 [2] 1e 4e [2] 59 4c [2] 1e 5d [2] 50 51 [2] 5c 5b [2] 4b 50 [2] 50 1e [2] 6d }

  condition:
    any of them
}