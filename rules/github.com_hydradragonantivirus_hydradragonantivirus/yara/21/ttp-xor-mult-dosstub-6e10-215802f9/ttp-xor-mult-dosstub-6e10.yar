rule TTP_XOR_MULT_DOSStub_6e10 {
  strings:
    $key_6e10 = { 3a 78 [2] 4e 60 [2] 09 62 [2] 4e 73 [2] 00 7f [2] 0c 75 [2] 1b 7e [2] 00 30 [2] 3d }

  condition:
    any of them
}