rule TTP_XOR_MULT_DOSStub_7f0e {
  strings:
    $key_7f0e = { 2b 66 [2] 5f 7e [2] 18 7c [2] 5f 6d [2] 11 61 [2] 1d 6b [2] 0a 60 [2] 11 2e [2] 2c }

  condition:
    any of them
}