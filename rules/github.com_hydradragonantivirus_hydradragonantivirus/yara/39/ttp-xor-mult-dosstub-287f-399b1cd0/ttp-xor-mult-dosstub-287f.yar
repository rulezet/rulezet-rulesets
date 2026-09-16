rule TTP_XOR_MULT_DOSStub_287f {
  strings:
    $key_287f = { 7c 17 [2] 08 0f [2] 4f 0d [2] 08 1c [2] 46 10 [2] 4a 1a [2] 5d 11 [2] 46 5f [2] 7b }

  condition:
    any of them
}