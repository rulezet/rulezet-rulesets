rule TTP_XOR_MULT_DOSStub_600f {
  strings:
    $key_600f = { 34 67 [2] 40 7f [2] 07 7d [2] 40 6c [2] 0e 60 [2] 02 6a [2] 15 61 [2] 0e 2f [2] 33 }

  condition:
    any of them
}