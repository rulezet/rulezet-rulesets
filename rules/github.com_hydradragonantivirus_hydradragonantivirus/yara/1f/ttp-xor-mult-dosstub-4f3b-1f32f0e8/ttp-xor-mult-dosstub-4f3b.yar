rule TTP_XOR_MULT_DOSStub_4f3b {
  strings:
    $key_4f3b = { 1b 53 [2] 6f 4b [2] 28 49 [2] 6f 58 [2] 21 54 [2] 2d 5e [2] 3a 55 [2] 21 1b [2] 1c }

  condition:
    any of them
}