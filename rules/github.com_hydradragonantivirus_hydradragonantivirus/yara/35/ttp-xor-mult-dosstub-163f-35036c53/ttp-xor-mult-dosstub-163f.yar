rule TTP_XOR_MULT_DOSStub_163f {
  strings:
    $key_163f = { 42 57 [2] 36 4f [2] 71 4d [2] 36 5c [2] 78 50 [2] 74 5a [2] 63 51 [2] 78 1f [2] 45 }

  condition:
    any of them
}