rule TTP_XOR_MULT_DOSStub_254e {
  strings:
    $key_254e = { 71 26 [2] 05 3e [2] 42 3c [2] 05 2d [2] 4b 21 [2] 47 2b [2] 50 20 [2] 4b 6e [2] 76 }

  condition:
    any of them
}