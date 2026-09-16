rule TTP_XOR_MULT_DOSStub_400f {
  strings:
    $key_400f = { 14 67 [2] 60 7f [2] 27 7d [2] 60 6c [2] 2e 60 [2] 22 6a [2] 35 61 [2] 2e 2f [2] 13 }

  condition:
    any of them
}