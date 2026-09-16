rule TTP_XOR_MULT_DOSStub_792b {
  strings:
    $key_792b = { 2d 43 [2] 59 5b [2] 1e 59 [2] 59 48 [2] 17 44 [2] 1b 4e [2] 0c 45 [2] 17 0b [2] 2a }

  condition:
    any of them
}