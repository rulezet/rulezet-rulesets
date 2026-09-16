rule TTP_XOR_MULT_DOSStub_4a1f {
  strings:
    $key_4a1f = { 1e 77 [2] 6a 6f [2] 2d 6d [2] 6a 7c [2] 24 70 [2] 28 7a [2] 3f 71 [2] 24 3f [2] 19 }

  condition:
    any of them
}