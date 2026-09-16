rule TTP_XOR_MULT_DOSStub_551f {
  strings:
    $key_551f = { 01 77 [2] 75 6f [2] 32 6d [2] 75 7c [2] 3b 70 [2] 37 7a [2] 20 71 [2] 3b 3f [2] 06 }

  condition:
    any of them
}