rule TTP_XOR_MULT_DOSStub_566f {
  strings:
    $key_566f = { 02 07 [2] 76 1f [2] 31 1d [2] 76 0c [2] 38 00 [2] 34 0a [2] 23 01 [2] 38 4f [2] 05 }

  condition:
    any of them
}