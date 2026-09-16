rule TTP_XOR_MULT_DOSStub_3f6e {
  strings:
    $key_3f6e = { 6b 06 [2] 1f 1e [2] 58 1c [2] 1f 0d [2] 51 01 [2] 5d 0b [2] 4a 00 [2] 51 4e [2] 6c }

  condition:
    any of them
}