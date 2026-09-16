rule TTP_XOR_MULT_DOSStub_7eea {
  strings:
    $key_7eea = { 2a 82 [2] 5e 9a [2] 19 98 [2] 5e 89 [2] 10 85 [2] 1c 8f [2] 0b 84 [2] 10 ca [2] 2d }

  condition:
    any of them
}