rule TTP_XOR_MULT_DOSStub_430d {
  strings:
    $key_430d = { 17 65 [2] 63 7d [2] 24 7f [2] 63 6e [2] 2d 62 [2] 21 68 [2] 36 63 [2] 2d 2d [2] 10 }

  condition:
    any of them
}