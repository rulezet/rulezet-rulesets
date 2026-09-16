rule TTP_XOR_MULT_DOSStub_1fea {
  strings:
    $key_1fea = { 4b 82 [2] 3f 9a [2] 78 98 [2] 3f 89 [2] 71 85 [2] 7d 8f [2] 6a 84 [2] 71 ca [2] 4c }

  condition:
    any of them
}