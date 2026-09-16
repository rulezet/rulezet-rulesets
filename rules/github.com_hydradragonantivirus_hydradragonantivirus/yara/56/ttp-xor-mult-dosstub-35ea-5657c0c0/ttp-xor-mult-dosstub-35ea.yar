rule TTP_XOR_MULT_DOSStub_35ea {
  strings:
    $key_35ea = { 61 82 [2] 15 9a [2] 52 98 [2] 15 89 [2] 5b 85 [2] 57 8f [2] 40 84 [2] 5b ca [2] 66 }

  condition:
    any of them
}