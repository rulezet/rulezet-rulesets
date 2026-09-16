rule TTP_XOR_MULT_DOSStub_684e {
  strings:
    $key_684e = { 3c 26 [2] 48 3e [2] 0f 3c [2] 48 2d [2] 06 21 [2] 0a 2b [2] 1d 20 [2] 06 6e [2] 3b }

  condition:
    any of them
}