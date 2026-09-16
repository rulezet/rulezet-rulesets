rule TTP_XOR_MULT_DOSStub_706f {
  strings:
    $key_706f = { 24 07 [2] 50 1f [2] 17 1d [2] 50 0c [2] 1e 00 [2] 12 0a [2] 05 01 [2] 1e 4f [2] 23 }

  condition:
    any of them
}