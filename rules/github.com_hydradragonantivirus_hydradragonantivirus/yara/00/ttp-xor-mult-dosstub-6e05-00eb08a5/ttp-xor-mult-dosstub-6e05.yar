rule TTP_XOR_MULT_DOSStub_6e05 {
  strings:
    $key_6e05 = { 3a 6d [2] 4e 75 [2] 09 77 [2] 4e 66 [2] 00 6a [2] 0c 60 [2] 1b 6b [2] 00 25 [2] 3d }

  condition:
    any of them
}