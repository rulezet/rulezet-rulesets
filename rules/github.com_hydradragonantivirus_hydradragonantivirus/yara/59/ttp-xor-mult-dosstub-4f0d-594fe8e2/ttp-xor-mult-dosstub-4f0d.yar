rule TTP_XOR_MULT_DOSStub_4f0d {
  strings:
    $key_4f0d = { 1b 65 [2] 6f 7d [2] 28 7f [2] 6f 6e [2] 21 62 [2] 2d 68 [2] 3a 63 [2] 21 2d [2] 1c }

  condition:
    any of them
}