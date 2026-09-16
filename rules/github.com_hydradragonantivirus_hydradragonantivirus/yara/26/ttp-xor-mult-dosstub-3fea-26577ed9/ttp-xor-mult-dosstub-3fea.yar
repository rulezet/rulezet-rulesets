rule TTP_XOR_MULT_DOSStub_3fea {
  strings:
    $key_3fea = { 6b 82 [2] 1f 9a [2] 58 98 [2] 1f 89 [2] 51 85 [2] 5d 8f [2] 4a 84 [2] 51 ca [2] 6c }

  condition:
    any of them
}