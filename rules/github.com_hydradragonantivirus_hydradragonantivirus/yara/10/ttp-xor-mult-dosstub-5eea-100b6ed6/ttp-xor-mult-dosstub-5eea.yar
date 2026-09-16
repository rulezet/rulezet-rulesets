rule TTP_XOR_MULT_DOSStub_5eea {
  strings:
    $key_5eea = { 0a 82 [2] 7e 9a [2] 39 98 [2] 7e 89 [2] 30 85 [2] 3c 8f [2] 2b 84 [2] 30 ca [2] 0d }

  condition:
    any of them
}