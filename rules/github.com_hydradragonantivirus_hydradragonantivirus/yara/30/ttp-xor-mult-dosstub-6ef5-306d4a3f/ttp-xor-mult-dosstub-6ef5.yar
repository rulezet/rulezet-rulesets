rule TTP_XOR_MULT_DOSStub_6ef5 {
  strings:
    $key_6ef5 = { 3a 9d [2] 4e 85 [2] 09 87 [2] 4e 96 [2] 00 9a [2] 0c 90 [2] 1b 9b [2] 00 d5 [2] 3d }

  condition:
    any of them
}