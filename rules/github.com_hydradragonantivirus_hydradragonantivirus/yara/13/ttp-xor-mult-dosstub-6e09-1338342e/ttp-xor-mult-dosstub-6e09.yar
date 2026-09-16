rule TTP_XOR_MULT_DOSStub_6e09 {
  strings:
    $key_6e09 = { 3a 61 [2] 4e 79 [2] 09 7b [2] 4e 6a [2] 00 66 [2] 0c 6c [2] 1b 67 [2] 00 29 [2] 3d }

  condition:
    any of them
}