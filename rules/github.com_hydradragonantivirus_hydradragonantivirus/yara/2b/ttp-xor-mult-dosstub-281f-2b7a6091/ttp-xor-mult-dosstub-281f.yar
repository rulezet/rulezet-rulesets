rule TTP_XOR_MULT_DOSStub_281f {
  strings:
    $key_281f = { 7c 77 [2] 08 6f [2] 4f 6d [2] 08 7c [2] 46 70 [2] 4a 7a [2] 5d 71 [2] 46 3f [2] 7b }

  condition:
    any of them
}