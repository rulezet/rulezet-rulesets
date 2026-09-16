rule TTP_XOR_MULT_DOSStub_64ea {
  strings:
    $key_64ea = { 30 82 [2] 44 9a [2] 03 98 [2] 44 89 [2] 0a 85 [2] 06 8f [2] 11 84 [2] 0a ca [2] 37 }

  condition:
    any of them
}