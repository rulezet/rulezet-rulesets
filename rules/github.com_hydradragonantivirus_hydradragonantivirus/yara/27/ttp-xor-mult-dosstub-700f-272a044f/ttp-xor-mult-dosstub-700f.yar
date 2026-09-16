rule TTP_XOR_MULT_DOSStub_700f {
  strings:
    $key_700f = { 24 67 [2] 50 7f [2] 17 7d [2] 50 6c [2] 1e 60 [2] 12 6a [2] 05 61 [2] 1e 2f [2] 23 }

  condition:
    any of them
}