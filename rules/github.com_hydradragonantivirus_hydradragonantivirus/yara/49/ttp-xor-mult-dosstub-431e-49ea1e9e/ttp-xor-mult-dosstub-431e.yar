rule TTP_XOR_MULT_DOSStub_431e {
  strings:
    $key_431e = { 17 76 [2] 63 6e [2] 24 6c [2] 63 7d [2] 2d 71 [2] 21 7b [2] 36 70 [2] 2d 3e [2] 10 }

  condition:
    any of them
}