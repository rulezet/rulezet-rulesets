rule TTP_XOR_MULT_DOSStub_58ea {
  strings:
    $key_58ea = { 0c 82 [2] 78 9a [2] 3f 98 [2] 78 89 [2] 36 85 [2] 3a 8f [2] 2d 84 [2] 36 ca [2] 0b }

  condition:
    any of them
}