rule TTP_XOR_MULT_DOSStub_25ea {
  strings:
    $key_25ea = { 71 82 [2] 05 9a [2] 42 98 [2] 05 89 [2] 4b 85 [2] 47 8f [2] 50 84 [2] 4b ca [2] 76 }

  condition:
    any of them
}