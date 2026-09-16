rule TTP_XOR_MULT_DOSStub_4f2b {
  strings:
    $key_4f2b = { 1b 43 [2] 6f 5b [2] 28 59 [2] 6f 48 [2] 21 44 [2] 2d 4e [2] 3a 45 [2] 21 0b [2] 1c }

  condition:
    any of them
}