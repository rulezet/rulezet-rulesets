rule TTP_XOR_MULT_DOSStub_70ea {
  strings:
    $key_70ea = { 24 82 [2] 50 9a [2] 17 98 [2] 50 89 [2] 1e 85 [2] 12 8f [2] 05 84 [2] 1e ca [2] 23 }

  condition:
    any of them
}