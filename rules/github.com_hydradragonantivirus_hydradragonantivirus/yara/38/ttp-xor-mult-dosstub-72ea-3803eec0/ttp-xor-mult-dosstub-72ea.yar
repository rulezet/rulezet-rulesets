rule TTP_XOR_MULT_DOSStub_72ea {
  strings:
    $key_72ea = { 26 82 [2] 52 9a [2] 15 98 [2] 52 89 [2] 1c 85 [2] 10 8f [2] 07 84 [2] 1c ca [2] 21 }

  condition:
    any of them
}