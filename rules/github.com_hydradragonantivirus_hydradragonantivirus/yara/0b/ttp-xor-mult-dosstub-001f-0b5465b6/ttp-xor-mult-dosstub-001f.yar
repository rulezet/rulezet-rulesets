rule TTP_XOR_MULT_DOSStub_001f {
  strings:
    $key_001f = { 54 77 [2] 20 6f [2] 67 6d [2] 20 7c [2] 6e 70 [2] 62 7a [2] 75 71 [2] 6e 3f [2] 53 }

  condition:
    any of them
}