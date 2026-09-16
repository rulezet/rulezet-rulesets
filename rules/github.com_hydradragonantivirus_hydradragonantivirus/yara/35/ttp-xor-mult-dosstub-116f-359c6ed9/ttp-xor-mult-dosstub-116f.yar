rule TTP_XOR_MULT_DOSStub_116f {
  strings:
    $key_116f = { 45 07 [2] 31 1f [2] 76 1d [2] 31 0c [2] 7f 00 [2] 73 0a [2] 64 01 [2] 7f 4f [2] 42 }

  condition:
    any of them
}