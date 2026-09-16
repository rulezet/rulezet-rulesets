rule TTP_XOR_MULT_DOSStub_485e {
  strings:
    $key_485e = { 1c 36 [2] 68 2e [2] 2f 2c [2] 68 3d [2] 26 31 [2] 2a 3b [2] 3d 30 [2] 26 7e [2] 1b }

  condition:
    any of them
}