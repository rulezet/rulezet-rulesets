rule TTP_XOR_MULT_DOSStub_711f {
  strings:
    $key_711f = { 25 77 [2] 51 6f [2] 16 6d [2] 51 7c [2] 1f 70 [2] 13 7a [2] 04 71 [2] 1f 3f [2] 22 }

  condition:
    any of them
}