rule TTP_XOR_MULT_DOSStub_2a0d {
  strings:
    $key_2a0d = { 7e 65 [2] 0a 7d [2] 4d 7f [2] 0a 6e [2] 44 62 [2] 48 68 [2] 5f 63 [2] 44 2d [2] 79 }

  condition:
    any of them
}