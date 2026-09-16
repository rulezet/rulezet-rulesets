rule TTP_XOR_MULT_DOSStub_6c0e {
  strings:
    $key_6c0e = { 38 66 [2] 4c 7e [2] 0b 7c [2] 4c 6d [2] 02 61 [2] 0e 6b [2] 19 60 [2] 02 2e [2] 3f }

  condition:
    any of them
}