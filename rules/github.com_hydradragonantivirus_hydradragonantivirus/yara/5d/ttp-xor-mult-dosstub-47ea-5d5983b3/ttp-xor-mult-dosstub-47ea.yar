rule TTP_XOR_MULT_DOSStub_47ea {
  strings:
    $key_47ea = { 13 82 [2] 67 9a [2] 20 98 [2] 67 89 [2] 29 85 [2] 25 8f [2] 32 84 [2] 29 ca [2] 14 }

  condition:
    any of them
}