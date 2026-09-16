rule TTP_XOR_MULT_DOSStub_435b {
  strings:
    $key_435b = { 17 33 [2] 63 2b [2] 24 29 [2] 63 38 [2] 2d 34 [2] 21 3e [2] 36 35 [2] 2d 7b [2] 10 }

  condition:
    any of them
}