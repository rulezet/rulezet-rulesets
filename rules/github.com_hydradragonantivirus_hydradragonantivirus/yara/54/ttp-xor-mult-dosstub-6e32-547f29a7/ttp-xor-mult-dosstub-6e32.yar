rule TTP_XOR_MULT_DOSStub_6e32 {
  strings:
    $key_6e32 = { 3a 5a [2] 4e 42 [2] 09 40 [2] 4e 51 [2] 00 5d [2] 0c 57 [2] 1b 5c [2] 00 12 [2] 3d }

  condition:
    any of them
}