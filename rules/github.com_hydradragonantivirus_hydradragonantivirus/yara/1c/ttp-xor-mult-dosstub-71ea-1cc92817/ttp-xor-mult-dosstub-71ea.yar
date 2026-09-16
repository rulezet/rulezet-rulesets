rule TTP_XOR_MULT_DOSStub_71ea {
  strings:
    $key_71ea = { 25 82 [2] 51 9a [2] 16 98 [2] 51 89 [2] 1f 85 [2] 13 8f [2] 04 84 [2] 1f ca [2] 22 }

  condition:
    any of them
}