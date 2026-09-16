rule TTP_XOR_MULT_DOSStub_432f {
  strings:
    $key_432f = { 17 47 [2] 63 5f [2] 24 5d [2] 63 4c [2] 2d 40 [2] 21 4a [2] 36 41 [2] 2d 0f [2] 10 }

  condition:
    any of them
}