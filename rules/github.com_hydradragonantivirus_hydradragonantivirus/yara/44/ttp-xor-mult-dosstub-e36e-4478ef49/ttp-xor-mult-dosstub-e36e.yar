rule TTP_XOR_MULT_DOSStub_e36e {
  strings:
    $key_e36e = { b7 06 [2] c3 1e [2] 84 1c [2] c3 0d [2] 8d 01 [2] 81 0b [2] 96 00 [2] 8d 4e [2] b0 }

  condition:
    any of them
}