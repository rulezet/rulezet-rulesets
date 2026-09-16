rule TTP_XOR_MULT_DOSStub_0b0d {
  strings:
    $key_0b0d = { 5f 65 [2] 2b 7d [2] 6c 7f [2] 2b 6e [2] 65 62 [2] 69 68 [2] 7e 63 [2] 65 2d [2] 58 }

  condition:
    any of them
}