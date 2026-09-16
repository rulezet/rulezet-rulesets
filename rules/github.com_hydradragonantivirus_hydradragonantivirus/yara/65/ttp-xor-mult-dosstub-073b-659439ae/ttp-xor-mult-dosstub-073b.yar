rule TTP_XOR_MULT_DOSStub_073b {
  strings:
    $key_073b = { 53 53 [2] 27 4b [2] 60 49 [2] 27 58 [2] 69 54 [2] 65 5e [2] 72 55 [2] 69 1b [2] 54 }

  condition:
    any of them
}