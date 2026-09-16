rule TTP_XOR_MULT_DOSStub_27ea {
  strings:
    $key_27ea = { 73 82 [2] 07 9a [2] 40 98 [2] 07 89 [2] 49 85 [2] 45 8f [2] 52 84 [2] 49 ca [2] 74 }

  condition:
    any of them
}