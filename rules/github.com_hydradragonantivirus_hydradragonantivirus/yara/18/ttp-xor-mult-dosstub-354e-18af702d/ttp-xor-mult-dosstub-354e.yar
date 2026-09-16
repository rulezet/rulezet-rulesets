rule TTP_XOR_MULT_DOSStub_354e {
  strings:
    $key_354e = { 61 26 [2] 15 3e [2] 52 3c [2] 15 2d [2] 5b 21 [2] 57 2b [2] 40 20 [2] 5b 6e [2] 66 }

  condition:
    any of them
}