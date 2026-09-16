rule TTP_XOR_MULT_DOSStub_46ea {
  strings:
    $key_46ea = { 12 82 [2] 66 9a [2] 21 98 [2] 66 89 [2] 28 85 [2] 24 8f [2] 33 84 [2] 28 ca [2] 15 }

  condition:
    any of them
}