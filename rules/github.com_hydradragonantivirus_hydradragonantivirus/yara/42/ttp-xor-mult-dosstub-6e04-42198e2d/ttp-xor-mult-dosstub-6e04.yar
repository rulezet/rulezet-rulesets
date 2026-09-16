rule TTP_XOR_MULT_DOSStub_6e04 {
  strings:
    $key_6e04 = { 3a 6c [2] 4e 74 [2] 09 76 [2] 4e 67 [2] 00 6b [2] 0c 61 [2] 1b 6a [2] 00 24 [2] 3d }

  condition:
    any of them
}