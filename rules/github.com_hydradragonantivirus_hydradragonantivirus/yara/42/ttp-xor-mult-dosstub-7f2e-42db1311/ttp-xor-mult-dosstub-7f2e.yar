rule TTP_XOR_MULT_DOSStub_7f2e {
  strings:
    $key_7f2e = { 2b 46 [2] 5f 5e [2] 18 5c [2] 5f 4d [2] 11 41 [2] 1d 4b [2] 0a 40 [2] 11 0e [2] 2c }

  condition:
    any of them
}