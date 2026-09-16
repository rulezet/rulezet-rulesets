rule TTP_XOR_MULT_DOSStub_795b {
  strings:
    $key_795b = { 2d 33 [2] 59 2b [2] 1e 29 [2] 59 38 [2] 17 34 [2] 1b 3e [2] 0c 35 [2] 17 7b [2] 2a }

  condition:
    any of them
}