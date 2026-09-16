rule TTP_XOR_MULT_DOSStub_200d {
  strings:
    $key_200d = { 74 65 [2] 00 7d [2] 47 7f [2] 00 6e [2] 4e 62 [2] 42 68 [2] 55 63 [2] 4e 2d [2] 73 }

  condition:
    any of them
}