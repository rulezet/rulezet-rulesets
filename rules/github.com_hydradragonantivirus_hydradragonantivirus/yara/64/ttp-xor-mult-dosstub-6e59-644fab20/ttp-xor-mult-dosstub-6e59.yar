rule TTP_XOR_MULT_DOSStub_6e59 {
  strings:
    $key_6e59 = { 3a 31 [2] 4e 29 [2] 09 2b [2] 4e 3a [2] 00 36 [2] 0c 3c [2] 1b 37 [2] 00 79 [2] 3d }

  condition:
    any of them
}