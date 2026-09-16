rule TTP_XOR_MULT_DOSStub_0d5f {
  strings:
    $key_0d5f = { 59 37 [2] 2d 2f [2] 6a 2d [2] 2d 3c [2] 63 30 [2] 6f 3a [2] 78 31 [2] 63 7f [2] 5e }

  condition:
    any of them
}