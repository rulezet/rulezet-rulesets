rule TTP_XOR_MULT_DOSStub_7dea {
  strings:
    $key_7dea = { 29 82 [2] 5d 9a [2] 1a 98 [2] 5d 89 [2] 13 85 [2] 1f 8f [2] 08 84 [2] 13 ca [2] 2e }

  condition:
    any of them
}