rule TTP_XOR_MULT_DOSStub_6e18 {
  strings:
    $key_6e18 = { 3a 70 [2] 4e 68 [2] 09 6a [2] 4e 7b [2] 00 77 [2] 0c 7d [2] 1b 76 [2] 00 38 [2] 3d }

  condition:
    any of them
}