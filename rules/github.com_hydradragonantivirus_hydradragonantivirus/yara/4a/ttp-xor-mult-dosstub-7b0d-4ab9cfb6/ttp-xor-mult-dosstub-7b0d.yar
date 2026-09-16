rule TTP_XOR_MULT_DOSStub_7b0d {
  strings:
    $key_7b0d = { 2f 65 [2] 5b 7d [2] 1c 7f [2] 5b 6e [2] 15 62 [2] 19 68 [2] 0e 63 [2] 15 2d [2] 28 }

  condition:
    any of them
}