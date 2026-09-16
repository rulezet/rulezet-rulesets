rule TTP_XOR_MULT_DOSStub_68ea {
  strings:
    $key_68ea = { 3c 82 [2] 48 9a [2] 0f 98 [2] 48 89 [2] 06 85 [2] 0a 8f [2] 1d 84 [2] 06 ca [2] 3b }

  condition:
    any of them
}