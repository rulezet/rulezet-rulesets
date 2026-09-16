rule TTP_XOR_MULT_DOSStub_0d0d {
  strings:
    $key_0d0d = { 59 65 [2] 2d 7d [2] 6a 7f [2] 2d 6e [2] 63 62 [2] 6f 68 [2] 78 63 [2] 63 2d [2] 5e }

  condition:
    any of them
}