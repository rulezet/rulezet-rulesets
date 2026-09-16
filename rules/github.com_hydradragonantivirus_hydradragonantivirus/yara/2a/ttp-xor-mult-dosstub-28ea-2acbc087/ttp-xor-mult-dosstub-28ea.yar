rule TTP_XOR_MULT_DOSStub_28ea {
  strings:
    $key_28ea = { 7c 82 [2] 08 9a [2] 4f 98 [2] 08 89 [2] 46 85 [2] 4a 8f [2] 5d 84 [2] 46 ca [2] 7b }

  condition:
    any of them
}