rule TTP_XOR_MULT_DOSStub_5a1f {
  strings:
    $key_5a1f = { 0e 77 [2] 7a 6f [2] 3d 6d [2] 7a 7c [2] 34 70 [2] 38 7a [2] 2f 71 [2] 34 3f [2] 09 }

  condition:
    any of them
}