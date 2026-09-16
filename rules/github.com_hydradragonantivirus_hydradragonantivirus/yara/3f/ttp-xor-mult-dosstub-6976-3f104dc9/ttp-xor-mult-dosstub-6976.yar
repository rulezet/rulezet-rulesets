rule TTP_XOR_MULT_DOSStub_6976 {
  strings:
    $key_6976 = { 3d 1e [2] 49 06 [2] 0e 04 [2] 49 15 [2] 07 19 [2] 0b 13 [2] 1c 18 [2] 07 56 [2] 3a }

  condition:
    any of them
}