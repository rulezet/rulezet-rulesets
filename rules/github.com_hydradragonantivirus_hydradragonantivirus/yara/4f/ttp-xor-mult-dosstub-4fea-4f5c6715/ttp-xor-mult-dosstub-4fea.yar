rule TTP_XOR_MULT_DOSStub_4fea {
  strings:
    $key_4fea = { 1b 82 [2] 6f 9a [2] 28 98 [2] 6f 89 [2] 21 85 [2] 2d 8f [2] 3a 84 [2] 21 ca [2] 1c }

  condition:
    any of them
}