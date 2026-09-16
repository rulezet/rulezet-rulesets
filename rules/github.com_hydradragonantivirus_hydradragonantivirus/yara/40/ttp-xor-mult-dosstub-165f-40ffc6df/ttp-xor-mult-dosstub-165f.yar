rule TTP_XOR_MULT_DOSStub_165f {
  strings:
    $key_165f = { 42 37 [2] 36 2f [2] 71 2d [2] 36 3c [2] 78 30 [2] 74 3a [2] 63 31 [2] 78 7f [2] 45 }

  condition:
    any of them
}