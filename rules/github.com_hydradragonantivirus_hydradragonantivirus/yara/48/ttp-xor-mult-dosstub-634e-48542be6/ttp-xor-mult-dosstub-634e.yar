rule TTP_XOR_MULT_DOSStub_634e {
  strings:
    $key_634e = { 37 26 [2] 43 3e [2] 04 3c [2] 43 2d [2] 0d 21 [2] 01 2b [2] 16 20 [2] 0d 6e [2] 30 }

  condition:
    any of them
}