rule TTP_XOR_MULT_DOSStub_2d2d {
  strings:
    $key_2d2d = { 79 45 [2] 0d 5d [2] 4a 5f [2] 0d 4e [2] 43 42 [2] 4f 48 [2] 58 43 [2] 43 0d [2] 7e }

  condition:
    any of them
}