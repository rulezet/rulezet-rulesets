rule TTP_XOR_MULT_DOSStub_12ea {
  strings:
    $key_12ea = { 46 82 [2] 32 9a [2] 75 98 [2] 32 89 [2] 7c 85 [2] 70 8f [2] 67 84 [2] 7c ca [2] 41 }

  condition:
    any of them
}