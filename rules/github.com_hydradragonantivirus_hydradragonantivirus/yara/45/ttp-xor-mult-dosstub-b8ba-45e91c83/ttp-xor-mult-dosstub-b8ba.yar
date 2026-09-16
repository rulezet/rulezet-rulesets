rule TTP_XOR_MULT_DOSStub_b8ba {
  strings:
    $key_b8ba = { ec d2 [2] 98 ca [2] df c8 [2] 98 d9 [2] d6 d5 [2] da df [2] cd d4 [2] d6 9a [2] eb }

  condition:
    any of them
}