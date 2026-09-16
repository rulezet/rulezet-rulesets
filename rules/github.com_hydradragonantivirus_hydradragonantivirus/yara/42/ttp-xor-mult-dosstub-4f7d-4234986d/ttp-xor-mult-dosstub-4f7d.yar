rule TTP_XOR_MULT_DOSStub_4f7d {
  strings:
    $key_4f7d = { 1b 15 [2] 6f 0d [2] 28 0f [2] 6f 1e [2] 21 12 [2] 2d 18 [2] 3a 13 [2] 21 5d [2] 1c }

  condition:
    any of them
}