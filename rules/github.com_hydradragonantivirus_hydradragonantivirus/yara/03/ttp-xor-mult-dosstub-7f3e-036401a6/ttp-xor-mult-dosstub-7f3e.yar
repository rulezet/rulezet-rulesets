rule TTP_XOR_MULT_DOSStub_7f3e {
  strings:
    $key_7f3e = { 2b 56 [2] 5f 4e [2] 18 4c [2] 5f 5d [2] 11 51 [2] 1d 5b [2] 0a 50 [2] 11 1e [2] 2c }

  condition:
    any of them
}