rule TTP_XOR_MULT_DOSStub_e76e {
  strings:
    $key_e76e = { b3 06 [2] c7 1e [2] 80 1c [2] c7 0d [2] 89 01 [2] 85 0b [2] 92 00 [2] 89 4e [2] b4 }

  condition:
    any of them
}