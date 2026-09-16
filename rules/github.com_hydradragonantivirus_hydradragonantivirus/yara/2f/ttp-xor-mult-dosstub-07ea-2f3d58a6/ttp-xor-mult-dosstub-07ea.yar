rule TTP_XOR_MULT_DOSStub_07ea {
  strings:
    $key_07ea = { 53 82 [2] 27 9a [2] 60 98 [2] 27 89 [2] 69 85 [2] 65 8f [2] 72 84 [2] 69 ca [2] 54 }

  condition:
    any of them
}