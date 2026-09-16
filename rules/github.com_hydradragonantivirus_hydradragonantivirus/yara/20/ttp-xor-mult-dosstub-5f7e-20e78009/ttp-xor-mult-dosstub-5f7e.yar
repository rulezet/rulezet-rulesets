rule TTP_XOR_MULT_DOSStub_5f7e {
  strings:
    $key_5f7e = { 0b 16 [2] 7f 0e [2] 38 0c [2] 7f 1d [2] 31 11 [2] 3d 1b [2] 2a 10 [2] 31 5e [2] 0c }

  condition:
    any of them
}