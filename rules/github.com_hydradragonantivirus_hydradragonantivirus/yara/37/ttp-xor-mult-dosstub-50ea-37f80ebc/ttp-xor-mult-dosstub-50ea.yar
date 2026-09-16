rule TTP_XOR_MULT_DOSStub_50ea {
  strings:
    $key_50ea = { 04 82 [2] 70 9a [2] 37 98 [2] 70 89 [2] 3e 85 [2] 32 8f [2] 25 84 [2] 3e ca [2] 03 }

  condition:
    any of them
}