rule TTP_XOR_MULT_DOSStub_4eea {
  strings:
    $key_4eea = { 1a 82 [2] 6e 9a [2] 29 98 [2] 6e 89 [2] 20 85 [2] 2c 8f [2] 3b 84 [2] 20 ca [2] 1d }

  condition:
    any of them
}