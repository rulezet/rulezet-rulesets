rule TTP_XOR_MULT_DOSStub_323b {
  strings:
    $key_323b = { 66 53 [2] 12 4b [2] 55 49 [2] 12 58 [2] 5c 54 [2] 50 5e [2] 47 55 [2] 5c 1b [2] 61 }

  condition:
    any of them
}