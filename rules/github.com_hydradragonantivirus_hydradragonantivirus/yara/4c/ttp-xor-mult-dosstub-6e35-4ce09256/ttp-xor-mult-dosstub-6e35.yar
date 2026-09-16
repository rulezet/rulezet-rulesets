rule TTP_XOR_MULT_DOSStub_6e35 {
  strings:
    $key_6e35 = { 3a 5d [2] 4e 45 [2] 09 47 [2] 4e 56 [2] 00 5a [2] 0c 50 [2] 1b 5b [2] 00 15 [2] 3d }

  condition:
    any of them
}