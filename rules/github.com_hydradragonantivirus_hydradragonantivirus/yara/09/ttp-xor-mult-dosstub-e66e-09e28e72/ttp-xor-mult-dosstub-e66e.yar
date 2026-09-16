rule TTP_XOR_MULT_DOSStub_e66e {
  strings:
    $key_e66e = { b2 06 [2] c6 1e [2] 81 1c [2] c6 0d [2] 88 01 [2] 84 0b [2] 93 00 [2] 88 4e [2] b5 }

  condition:
    any of them
}