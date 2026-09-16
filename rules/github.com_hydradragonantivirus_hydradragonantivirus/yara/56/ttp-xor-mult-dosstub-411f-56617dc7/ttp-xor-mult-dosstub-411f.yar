rule TTP_XOR_MULT_DOSStub_411f {
  strings:
    $key_411f = { 15 77 [2] 61 6f [2] 26 6d [2] 61 7c [2] 2f 70 [2] 23 7a [2] 34 71 [2] 2f 3f [2] 12 }

  condition:
    any of them
}