rule TTP_XOR_MULT_DOSStub_31ea {
  strings:
    $key_31ea = { 65 82 [2] 11 9a [2] 56 98 [2] 11 89 [2] 5f 85 [2] 53 8f [2] 44 84 [2] 5f ca [2] 62 }

  condition:
    any of them
}