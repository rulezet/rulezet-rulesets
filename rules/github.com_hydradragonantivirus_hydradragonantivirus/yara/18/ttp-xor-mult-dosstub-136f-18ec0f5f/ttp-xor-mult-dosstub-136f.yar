rule TTP_XOR_MULT_DOSStub_136f {
  strings:
    $key_136f = { 47 07 [2] 33 1f [2] 74 1d [2] 33 0c [2] 7d 00 [2] 71 0a [2] 66 01 [2] 7d 4f [2] 40 }

  condition:
    any of them
}