rule TTP_XOR_MULT_DOSStub_0d6e {
  strings:
    $key_0d6e = { 59 06 [2] 2d 1e [2] 6a 1c [2] 2d 0d [2] 63 01 [2] 6f 0b [2] 78 00 [2] 63 4e [2] 5e }

  condition:
    any of them
}