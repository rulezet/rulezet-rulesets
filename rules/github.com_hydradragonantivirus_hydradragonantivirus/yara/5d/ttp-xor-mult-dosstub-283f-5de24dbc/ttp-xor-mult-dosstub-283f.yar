rule TTP_XOR_MULT_DOSStub_283f {
  strings:
    $key_283f = { 7c 57 [2] 08 4f [2] 4f 4d [2] 08 5c [2] 46 50 [2] 4a 5a [2] 5d 51 [2] 46 1f [2] 7b }

  condition:
    any of them
}