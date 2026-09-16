rule TTP_XOR_MULT_DOSStub_3a1f {
  strings:
    $key_3a1f = { 6e 77 [2] 1a 6f [2] 5d 6d [2] 1a 7c [2] 54 70 [2] 58 7a [2] 4f 71 [2] 54 3f [2] 69 }

  condition:
    any of them
}