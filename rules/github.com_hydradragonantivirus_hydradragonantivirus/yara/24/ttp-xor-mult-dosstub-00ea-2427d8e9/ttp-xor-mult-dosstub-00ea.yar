rule TTP_XOR_MULT_DOSStub_00ea {
  strings:
    $key_00ea = { 54 82 [2] 20 9a [2] 67 98 [2] 20 89 [2] 6e 85 [2] 62 8f [2] 75 84 [2] 6e ca [2] 53 }

  condition:
    any of them
}