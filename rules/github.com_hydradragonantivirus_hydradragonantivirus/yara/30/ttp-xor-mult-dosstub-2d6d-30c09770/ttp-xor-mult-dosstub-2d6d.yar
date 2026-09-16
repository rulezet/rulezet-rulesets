rule TTP_XOR_MULT_DOSStub_2d6d {
  strings:
    $key_2d6d = { 79 05 [2] 0d 1d [2] 4a 1f [2] 0d 0e [2] 43 02 [2] 4f 08 [2] 58 03 [2] 43 4d [2] 7e }

  condition:
    any of them
}