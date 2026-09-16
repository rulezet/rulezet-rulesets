rule TTP_XOR_MULT_DOSStub_275f {
  strings:
    $key_275f = { 73 37 [2] 07 2f [2] 40 2d [2] 07 3c [2] 49 30 [2] 45 3a [2] 52 31 [2] 49 7f [2] 74 }

  condition:
    any of them
}