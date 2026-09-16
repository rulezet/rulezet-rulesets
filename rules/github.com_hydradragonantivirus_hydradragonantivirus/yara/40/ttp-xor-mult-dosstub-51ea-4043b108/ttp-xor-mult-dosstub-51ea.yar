rule TTP_XOR_MULT_DOSStub_51ea {
  strings:
    $key_51ea = { 05 82 [2] 71 9a [2] 36 98 [2] 71 89 [2] 3f 85 [2] 33 8f [2] 24 84 [2] 3f ca [2] 02 }

  condition:
    any of them
}