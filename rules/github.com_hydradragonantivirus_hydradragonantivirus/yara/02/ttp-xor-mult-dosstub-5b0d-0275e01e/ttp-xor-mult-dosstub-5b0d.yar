rule TTP_XOR_MULT_DOSStub_5b0d {
  strings:
    $key_5b0d = { 0f 65 [2] 7b 7d [2] 3c 7f [2] 7b 6e [2] 35 62 [2] 39 68 [2] 2e 63 [2] 35 2d [2] 08 }

  condition:
    any of them
}