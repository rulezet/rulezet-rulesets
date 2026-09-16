rule TTP_XOR_MULT_DOSStub_430f {
  strings:
    $key_430f = { 17 67 [2] 63 7f [2] 24 7d [2] 63 6c [2] 2d 60 [2] 21 6a [2] 36 61 [2] 2d 2f [2] 10 }

  condition:
    any of them
}