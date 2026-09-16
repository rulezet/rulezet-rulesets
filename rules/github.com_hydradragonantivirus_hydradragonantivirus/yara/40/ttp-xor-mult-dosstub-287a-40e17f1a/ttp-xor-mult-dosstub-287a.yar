rule TTP_XOR_MULT_DOSStub_287a {
  strings:
    $key_287a = { 7c 12 [2] 08 0a [2] 4f 08 [2] 08 19 [2] 46 15 [2] 4a 1f [2] 5d 14 [2] 46 5a [2] 7b }

  condition:
    any of them
}