rule TTP_XOR_MULT_DOSStub_6f5e {
  strings:
    $key_6f5e = { 3b 36 [2] 4f 2e [2] 08 2c [2] 4f 3d [2] 01 31 [2] 0d 3b [2] 1a 30 [2] 01 7e [2] 3c }

  condition:
    any of them
}