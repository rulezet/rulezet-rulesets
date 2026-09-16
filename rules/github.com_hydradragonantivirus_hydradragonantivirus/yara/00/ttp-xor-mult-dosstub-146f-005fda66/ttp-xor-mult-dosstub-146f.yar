rule TTP_XOR_MULT_DOSStub_146f {
  strings:
    $key_146f = { 40 07 [2] 34 1f [2] 73 1d [2] 34 0c [2] 7a 00 [2] 76 0a [2] 61 01 [2] 7a 4f [2] 47 }

  condition:
    any of them
}