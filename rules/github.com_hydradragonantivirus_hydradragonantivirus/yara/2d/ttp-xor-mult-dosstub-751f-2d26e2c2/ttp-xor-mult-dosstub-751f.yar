rule TTP_XOR_MULT_DOSStub_751f {
  strings:
    $key_751f = { 21 77 [2] 55 6f [2] 12 6d [2] 55 7c [2] 1b 70 [2] 17 7a [2] 00 71 [2] 1b 3f [2] 26 }

  condition:
    any of them
}