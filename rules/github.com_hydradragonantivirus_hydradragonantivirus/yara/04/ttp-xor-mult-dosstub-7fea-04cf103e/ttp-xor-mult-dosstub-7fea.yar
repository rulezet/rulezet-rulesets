rule TTP_XOR_MULT_DOSStub_7fea {
  strings:
    $key_7fea = { 2b 82 [2] 5f 9a [2] 18 98 [2] 5f 89 [2] 11 85 [2] 1d 8f [2] 0a 84 [2] 11 ca [2] 2c }

  condition:
    any of them
}