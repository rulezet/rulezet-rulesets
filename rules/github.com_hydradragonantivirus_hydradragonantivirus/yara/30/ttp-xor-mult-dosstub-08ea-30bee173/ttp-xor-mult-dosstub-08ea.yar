rule TTP_XOR_MULT_DOSStub_08ea {
  strings:
    $key_08ea = { 5c 82 [2] 28 9a [2] 6f 98 [2] 28 89 [2] 66 85 [2] 6a 8f [2] 7d 84 [2] 66 ca [2] 5b }

  condition:
    any of them
}