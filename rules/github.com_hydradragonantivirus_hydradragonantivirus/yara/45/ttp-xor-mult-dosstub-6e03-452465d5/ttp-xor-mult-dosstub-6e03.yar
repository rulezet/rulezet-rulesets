rule TTP_XOR_MULT_DOSStub_6e03 {
  strings:
    $key_6e03 = { 3a 6b [2] 4e 73 [2] 09 71 [2] 4e 60 [2] 00 6c [2] 0c 66 [2] 1b 6d [2] 00 23 [2] 3d }

  condition:
    any of them
}