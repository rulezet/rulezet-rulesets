rule TTP_XOR_MULT_DOSStub_506f {
  strings:
    $key_506f = { 04 07 [2] 70 1f [2] 37 1d [2] 70 0c [2] 3e 00 [2] 32 0a [2] 25 01 [2] 3e 4f [2] 03 }

  condition:
    any of them
}