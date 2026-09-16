rule TTP_XOR_MULT_DOSStub_69ea {
  strings:
    $key_69ea = { 3d 82 [2] 49 9a [2] 0e 98 [2] 49 89 [2] 07 85 [2] 0b 8f [2] 1c 84 [2] 07 ca [2] 3a }

  condition:
    any of them
}