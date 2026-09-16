rule TTP_XOR_MULT_DOSStub_e46e {
  strings:
    $key_e46e = { b0 06 [2] c4 1e [2] 83 1c [2] c4 0d [2] 8a 01 [2] 86 0b [2] 91 00 [2] 8a 4e [2] b7 }

  condition:
    any of them
}