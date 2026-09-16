rule TTP_XOR_MULT_DOSStub_6e28 {
  strings:
    $key_6e28 = { 3a 40 [2] 4e 58 [2] 09 5a [2] 4e 4b [2] 00 47 [2] 0c 4d [2] 1b 46 [2] 00 08 [2] 3d }

  condition:
    any of them
}