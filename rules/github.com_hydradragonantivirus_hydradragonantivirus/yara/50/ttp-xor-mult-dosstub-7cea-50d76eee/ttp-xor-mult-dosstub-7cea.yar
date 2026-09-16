rule TTP_XOR_MULT_DOSStub_7cea {
  strings:
    $key_7cea = { 28 82 [2] 5c 9a [2] 1b 98 [2] 5c 89 [2] 12 85 [2] 1e 8f [2] 09 84 [2] 12 ca [2] 2f }

  condition:
    any of them
}