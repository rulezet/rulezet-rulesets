rule TTP_XOR_MULT_DOSStub_66ea {
  strings:
    $key_66ea = { 32 82 [2] 46 9a [2] 01 98 [2] 46 89 [2] 08 85 [2] 04 8f [2] 13 84 [2] 08 ca [2] 35 }

  condition:
    any of them
}