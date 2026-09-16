rule TTP_XOR_MULT_DOSStub_6a0d {
  strings:
    $key_6a0d = { 3e 65 [2] 4a 7d [2] 0d 7f [2] 4a 6e [2] 04 62 [2] 08 68 [2] 1f 63 [2] 04 2d [2] 39 }

  condition:
    any of them
}