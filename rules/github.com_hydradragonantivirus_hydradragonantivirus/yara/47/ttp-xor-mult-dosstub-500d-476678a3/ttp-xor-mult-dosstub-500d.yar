rule TTP_XOR_MULT_DOSStub_500d {
  strings:
    $key_500d = { 04 65 [2] 70 7d [2] 37 7f [2] 70 6e [2] 3e 62 [2] 32 68 [2] 25 63 [2] 3e 2d [2] 03 }

  condition:
    any of them
}