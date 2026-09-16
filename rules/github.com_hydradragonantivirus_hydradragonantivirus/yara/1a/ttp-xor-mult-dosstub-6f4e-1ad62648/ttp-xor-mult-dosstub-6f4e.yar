rule TTP_XOR_MULT_DOSStub_6f4e {
  strings:
    $key_6f4e = { 3b 26 [2] 4f 3e [2] 08 3c [2] 4f 2d [2] 01 21 [2] 0d 2b [2] 1a 20 [2] 01 6e [2] 3c }

  condition:
    any of them
}