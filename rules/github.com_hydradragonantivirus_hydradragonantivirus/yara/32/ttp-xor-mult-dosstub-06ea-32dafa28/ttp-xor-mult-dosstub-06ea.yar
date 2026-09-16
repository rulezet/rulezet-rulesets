rule TTP_XOR_MULT_DOSStub_06ea {
  strings:
    $key_06ea = { 52 82 [2] 26 9a [2] 61 98 [2] 26 89 [2] 68 85 [2] 64 8f [2] 73 84 [2] 68 ca [2] 55 }

  condition:
    any of them
}