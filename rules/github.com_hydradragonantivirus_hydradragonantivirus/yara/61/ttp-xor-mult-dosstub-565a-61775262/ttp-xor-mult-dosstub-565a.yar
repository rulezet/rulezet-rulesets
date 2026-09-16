rule TTP_XOR_MULT_DOSStub_565a {
  strings:
    $key_565a = { 02 32 [2] 76 2a [2] 31 28 [2] 76 39 [2] 38 35 [2] 34 3f [2] 23 34 [2] 38 7a [2] 05 }

  condition:
    any of them
}