rule TTP_XOR_MULT_DOSStub_e06e {
  strings:
    $key_e06e = { b4 06 [2] c0 1e [2] 87 1c [2] c0 0d [2] 8e 01 [2] 82 0b [2] 95 00 [2] 8e 4e [2] b3 }

  condition:
    any of them
}