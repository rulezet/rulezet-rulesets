rule TTP_XOR_MULT_DOSStub_2f6e {
  strings:
    $key_2f6e = { 7b 06 [2] 0f 1e [2] 48 1c [2] 0f 0d [2] 41 01 [2] 4d 0b [2] 5a 00 [2] 41 4e [2] 7c }

  condition:
    any of them
}