rule TTP_XOR_MULT_DOSStub_6e30 {
  strings:
    $key_6e30 = { 3a 58 [2] 4e 40 [2] 09 42 [2] 4e 53 [2] 00 5f [2] 0c 55 [2] 1b 5e [2] 00 10 [2] 3d }

  condition:
    any of them
}