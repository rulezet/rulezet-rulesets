rule TTP_XOR_MULT_DOSStub_055f {
  strings:
    $key_055f = { 51 37 [2] 25 2f [2] 62 2d [2] 25 3c [2] 6b 30 [2] 67 3a [2] 70 31 [2] 6b 7f [2] 56 }

  condition:
    any of them
}