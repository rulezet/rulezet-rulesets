rule TTP_XOR_MULT_DOSStub_6f6e {
  strings:
    $key_6f6e = { 3b 06 [2] 4f 1e [2] 08 1c [2] 4f 0d [2] 01 01 [2] 0d 0b [2] 1a 00 [2] 01 4e [2] 3c }

  condition:
    any of them
}