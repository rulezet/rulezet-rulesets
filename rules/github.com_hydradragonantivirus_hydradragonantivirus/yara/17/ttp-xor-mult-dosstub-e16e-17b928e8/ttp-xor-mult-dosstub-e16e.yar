rule TTP_XOR_MULT_DOSStub_e16e {
  strings:
    $key_e16e = { b5 06 [2] c1 1e [2] 86 1c [2] c1 0d [2] 8f 01 [2] 83 0b [2] 94 00 [2] 8f 4e [2] b2 }

  condition:
    any of them
}