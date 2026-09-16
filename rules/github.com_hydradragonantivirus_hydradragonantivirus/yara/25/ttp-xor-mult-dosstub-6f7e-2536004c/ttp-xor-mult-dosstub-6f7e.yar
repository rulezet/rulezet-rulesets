rule TTP_XOR_MULT_DOSStub_6f7e {
  strings:
    $key_6f7e = { 3b 16 [2] 4f 0e [2] 08 0c [2] 4f 1d [2] 01 11 [2] 0d 1b [2] 1a 10 [2] 01 5e [2] 3c }

  condition:
    any of them
}