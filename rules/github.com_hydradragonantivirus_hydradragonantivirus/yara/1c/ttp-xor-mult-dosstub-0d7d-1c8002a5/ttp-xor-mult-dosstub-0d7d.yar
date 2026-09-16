rule TTP_XOR_MULT_DOSStub_0d7d {
  strings:
    $key_0d7d = { 59 15 [2] 2d 0d [2] 6a 0f [2] 2d 1e [2] 63 12 [2] 6f 18 [2] 78 13 [2] 63 5d [2] 5e }

  condition:
    any of them
}