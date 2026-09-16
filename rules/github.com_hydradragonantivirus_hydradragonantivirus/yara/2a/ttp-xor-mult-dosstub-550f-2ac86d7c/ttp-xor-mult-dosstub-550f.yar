rule TTP_XOR_MULT_DOSStub_550f {
  strings:
    $key_550f = { 01 67 [2] 75 7f [2] 32 7d [2] 75 6c [2] 3b 60 [2] 37 6a [2] 20 61 [2] 3b 2f [2] 06 }

  condition:
    any of them
}