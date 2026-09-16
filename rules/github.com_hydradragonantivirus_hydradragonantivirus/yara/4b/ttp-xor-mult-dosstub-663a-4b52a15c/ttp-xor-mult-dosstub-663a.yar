rule TTP_XOR_MULT_DOSStub_663a {
  strings:
    $key_663a = { 32 52 [2] 46 4a [2] 01 48 [2] 46 59 [2] 08 55 [2] 04 5f [2] 13 54 [2] 08 1a [2] 35 }

  condition:
    any of them
}