rule TTP_XOR_MULT_DOSStub_6f0d {
  strings:
    $key_6f0d = { 3b 65 [2] 4f 7d [2] 08 7f [2] 4f 6e [2] 01 62 [2] 0d 68 [2] 1a 63 [2] 01 2d [2] 3c }

  condition:
    any of them
}