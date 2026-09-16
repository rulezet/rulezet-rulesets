rule TTP_XOR_MULT_DOSStub_6e36 {
  strings:
    $key_6e36 = { 3a 5e [2] 4e 46 [2] 09 44 [2] 4e 55 [2] 00 59 [2] 0c 53 [2] 1b 58 [2] 00 16 [2] 3d }

  condition:
    any of them
}