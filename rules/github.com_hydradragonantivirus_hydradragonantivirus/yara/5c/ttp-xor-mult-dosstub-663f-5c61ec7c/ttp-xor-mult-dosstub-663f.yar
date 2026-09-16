rule TTP_XOR_MULT_DOSStub_663f {
  strings:
    $key_663f = { 32 57 [2] 46 4f [2] 01 4d [2] 46 5c [2] 08 50 [2] 04 5a [2] 13 51 [2] 08 1f [2] 35 }

  condition:
    any of them
}