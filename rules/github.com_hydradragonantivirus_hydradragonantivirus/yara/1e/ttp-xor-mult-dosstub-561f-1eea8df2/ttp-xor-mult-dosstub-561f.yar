rule TTP_XOR_MULT_DOSStub_561f {
  strings:
    $key_561f = { 02 77 [2] 76 6f [2] 31 6d [2] 76 7c [2] 38 70 [2] 34 7a [2] 23 71 [2] 38 3f [2] 05 }

  condition:
    any of them
}