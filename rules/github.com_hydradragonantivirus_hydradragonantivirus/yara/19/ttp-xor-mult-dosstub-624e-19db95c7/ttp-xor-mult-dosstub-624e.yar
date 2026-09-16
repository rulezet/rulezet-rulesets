rule TTP_XOR_MULT_DOSStub_624e {
  strings:
    $key_624e = { 36 26 [2] 42 3e [2] 05 3c [2] 42 2d [2] 0c 21 [2] 00 2b [2] 17 20 [2] 0c 6e [2] 31 }

  condition:
    any of them
}