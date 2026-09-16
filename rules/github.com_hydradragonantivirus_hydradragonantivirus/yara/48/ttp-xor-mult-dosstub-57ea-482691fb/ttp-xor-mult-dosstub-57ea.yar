rule TTP_XOR_MULT_DOSStub_57ea {
  strings:
    $key_57ea = { 03 82 [2] 77 9a [2] 30 98 [2] 77 89 [2] 39 85 [2] 35 8f [2] 22 84 [2] 39 ca [2] 04 }

  condition:
    any of them
}