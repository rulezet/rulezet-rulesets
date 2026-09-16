rule TTP_XOR_MULT_DOSStub_5dea {
  strings:
    $key_5dea = { 09 82 [2] 7d 9a [2] 3a 98 [2] 7d 89 [2] 33 85 [2] 3f 8f [2] 28 84 [2] 33 ca [2] 0e }

  condition:
    any of them
}