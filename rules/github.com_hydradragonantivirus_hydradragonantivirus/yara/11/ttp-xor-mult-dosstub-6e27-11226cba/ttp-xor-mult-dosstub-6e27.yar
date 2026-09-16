rule TTP_XOR_MULT_DOSStub_6e27 {
  strings:
    $key_6e27 = { 3a 4f [2] 4e 57 [2] 09 55 [2] 4e 44 [2] 00 48 [2] 0c 42 [2] 1b 49 [2] 00 07 [2] 3d }

  condition:
    any of them
}