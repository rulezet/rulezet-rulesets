rule TTP_XOR_MULT_DOSStub_6e20 {
  strings:
    $key_6e20 = { 3a 48 [2] 4e 50 [2] 09 52 [2] 4e 43 [2] 00 4f [2] 0c 45 [2] 1b 4e [2] 00 00 [2] 3d }

  condition:
    any of them
}