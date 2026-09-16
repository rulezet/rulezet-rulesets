rule TTP_XOR_MULT_DOSStub_4f4e {
  strings:
    $key_4f4e = { 1b 26 [2] 6f 3e [2] 28 3c [2] 6f 2d [2] 21 21 [2] 2d 2b [2] 3a 20 [2] 21 6e [2] 1c }

  condition:
    any of them
}