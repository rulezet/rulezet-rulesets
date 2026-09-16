rule TTP_XOR_MULT_DOSStub_e56e {
  strings:
    $key_e56e = { b1 06 [2] c5 1e [2] 82 1c [2] c5 0d [2] 8b 01 [2] 87 0b [2] 90 00 [2] 8b 4e [2] b6 }

  condition:
    any of them
}