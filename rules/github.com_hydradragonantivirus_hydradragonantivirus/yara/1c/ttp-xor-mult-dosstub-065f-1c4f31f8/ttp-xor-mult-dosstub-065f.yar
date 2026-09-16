rule TTP_XOR_MULT_DOSStub_065f {
  strings:
    $key_065f = { 52 37 [2] 26 2f [2] 61 2d [2] 26 3c [2] 68 30 [2] 64 3a [2] 73 31 [2] 68 7f [2] 55 }

  condition:
    any of them
}