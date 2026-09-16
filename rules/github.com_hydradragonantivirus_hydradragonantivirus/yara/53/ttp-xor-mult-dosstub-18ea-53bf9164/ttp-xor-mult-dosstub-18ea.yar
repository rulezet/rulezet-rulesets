rule TTP_XOR_MULT_DOSStub_18ea {
  strings:
    $key_18ea = { 4c 82 [2] 38 9a [2] 7f 98 [2] 38 89 [2] 76 85 [2] 7a 8f [2] 6d 84 [2] 76 ca [2] 4b }

  condition:
    any of them
}