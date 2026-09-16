rule TTP_XOR_MULT_DOSStub_3eea {
  strings:
    $key_3eea = { 6a 82 [2] 1e 9a [2] 59 98 [2] 1e 89 [2] 50 85 [2] 5c 8f [2] 4b 84 [2] 50 ca [2] 6d }

  condition:
    any of them
}