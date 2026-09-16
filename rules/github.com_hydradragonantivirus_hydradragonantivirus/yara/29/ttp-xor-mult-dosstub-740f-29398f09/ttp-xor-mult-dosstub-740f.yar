rule TTP_XOR_MULT_DOSStub_740f {
  strings:
    $key_740f = { 20 67 [2] 54 7f [2] 13 7d [2] 54 6c [2] 1a 60 [2] 16 6a [2] 01 61 [2] 1a 2f [2] 27 }

  condition:
    any of them
}