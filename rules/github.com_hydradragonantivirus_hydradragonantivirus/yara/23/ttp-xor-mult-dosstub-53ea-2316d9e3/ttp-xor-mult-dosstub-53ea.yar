rule TTP_XOR_MULT_DOSStub_53ea {
  strings:
    $key_53ea = { 07 82 [2] 73 9a [2] 34 98 [2] 73 89 [2] 3d 85 [2] 31 8f [2] 26 84 [2] 3d ca [2] 00 }

  condition:
    any of them
}