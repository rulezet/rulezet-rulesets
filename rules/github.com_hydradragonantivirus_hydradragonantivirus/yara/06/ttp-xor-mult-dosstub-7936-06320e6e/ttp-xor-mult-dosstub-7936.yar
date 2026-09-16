rule TTP_XOR_MULT_DOSStub_7936 {
  strings:
    $key_7936 = { 2d 5e [2] 59 46 [2] 1e 44 [2] 59 55 [2] 17 59 [2] 1b 53 [2] 0c 58 [2] 17 16 [2] 2a }

  condition:
    any of them
}