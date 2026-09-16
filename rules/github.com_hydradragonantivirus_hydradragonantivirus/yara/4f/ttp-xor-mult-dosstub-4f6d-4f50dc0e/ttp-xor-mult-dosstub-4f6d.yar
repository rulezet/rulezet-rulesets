rule TTP_XOR_MULT_DOSStub_4f6d {
  strings:
    $key_4f6d = { 1b 05 [2] 6f 1d [2] 28 1f [2] 6f 0e [2] 21 02 [2] 2d 08 [2] 3a 03 [2] 21 4d [2] 1c }

  condition:
    any of them
}