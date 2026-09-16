rule TTP_XOR_MULT_DOSStub_1a1f {
  strings:
    $key_1a1f = { 4e 77 [2] 3a 6f [2] 7d 6d [2] 3a 7c [2] 74 70 [2] 78 7a [2] 6f 71 [2] 74 3f [2] 49 }

  condition:
    any of them
}