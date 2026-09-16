rule TTP_XOR_MULT_DOSStub_6fea {
  strings:
    $key_6fea = { 3b 82 [2] 4f 9a [2] 08 98 [2] 4f 89 [2] 01 85 [2] 0d 8f [2] 1a 84 [2] 01 ca [2] 3c }

  condition:
    any of them
}