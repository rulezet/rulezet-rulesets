rule TTP_XOR_MULT_DOSStub_6e62 {
  strings:
    $key_6e62 = { 3a 0a [2] 4e 12 [2] 09 10 [2] 4e 01 [2] 00 0d [2] 0c 07 [2] 1b 0c [2] 00 42 [2] 3d }

  condition:
    any of them
}