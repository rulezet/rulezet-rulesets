rule TTP_XOR_MULT_DOSStub_791b {
  strings:
    $key_791b = { 2d 73 [2] 59 6b [2] 1e 69 [2] 59 78 [2] 17 74 [2] 1b 7e [2] 0c 75 [2] 17 3b [2] 2a }

  condition:
    any of them
}