rule TTP_XOR_MULT_DOSStub_064e {
  strings:
    $key_064e = { 52 26 [2] 26 3e [2] 61 3c [2] 26 2d [2] 68 21 [2] 64 2b [2] 73 20 [2] 68 6e [2] 55 }

  condition:
    any of them
}