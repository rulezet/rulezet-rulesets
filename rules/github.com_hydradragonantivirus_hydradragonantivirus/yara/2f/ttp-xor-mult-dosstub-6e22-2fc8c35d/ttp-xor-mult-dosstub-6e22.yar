rule TTP_XOR_MULT_DOSStub_6e22 {
  strings:
    $key_6e22 = { 3a 4a [2] 4e 52 [2] 09 50 [2] 4e 41 [2] 00 4d [2] 0c 47 [2] 1b 4c [2] 00 02 [2] 3d }

  condition:
    any of them
}