rule TTP_XOR_MULT_DOSStub_7aea {
  strings:
    $key_7aea = { 2e 82 [2] 5a 9a [2] 1d 98 [2] 5a 89 [2] 14 85 [2] 18 8f [2] 0f 84 [2] 14 ca [2] 29 }

  condition:
    any of them
}