rule TTP_XOR_MULT_DOSStub_6e76 {
  strings:
    $key_6e76 = { 3a 1e [2] 4e 06 [2] 09 04 [2] 4e 15 [2] 00 19 [2] 0c 13 [2] 1b 18 [2] 00 56 [2] 3d }

  condition:
    any of them
}