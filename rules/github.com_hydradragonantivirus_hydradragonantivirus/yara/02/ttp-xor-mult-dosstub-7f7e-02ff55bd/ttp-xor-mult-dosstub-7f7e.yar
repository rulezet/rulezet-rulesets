rule TTP_XOR_MULT_DOSStub_7f7e {
  strings:
    $key_7f7e = { 2b 16 [2] 5f 0e [2] 18 0c [2] 5f 1d [2] 11 11 [2] 1d 1b [2] 0a 10 [2] 11 5e [2] 2c }

  condition:
    any of them
}