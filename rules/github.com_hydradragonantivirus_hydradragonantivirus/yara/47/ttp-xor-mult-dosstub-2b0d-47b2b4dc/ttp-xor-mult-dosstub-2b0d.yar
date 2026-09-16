rule TTP_XOR_MULT_DOSStub_2b0d {
  strings:
    $key_2b0d = { 7f 65 [2] 0b 7d [2] 4c 7f [2] 0b 6e [2] 45 62 [2] 49 68 [2] 5e 63 [2] 45 2d [2] 78 }

  condition:
    any of them
}