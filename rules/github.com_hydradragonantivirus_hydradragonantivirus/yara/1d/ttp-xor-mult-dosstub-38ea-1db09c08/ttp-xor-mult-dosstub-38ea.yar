rule TTP_XOR_MULT_DOSStub_38ea {
  strings:
    $key_38ea = { 6c 82 [2] 18 9a [2] 5f 98 [2] 18 89 [2] 56 85 [2] 5a 8f [2] 4d 84 [2] 56 ca [2] 6b }

  condition:
    any of them
}