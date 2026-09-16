rule TTP_XOR_MULT_DOSStub_33ea {
  strings:
    $key_33ea = { 67 82 [2] 13 9a [2] 54 98 [2] 13 89 [2] 5d 85 [2] 51 8f [2] 46 84 [2] 5d ca [2] 60 }

  condition:
    any of them
}