rule TTP_XOR_MULT_DOSStub_6eea {
  strings:
    $key_6eea = { 3a 82 [2] 4e 9a [2] 09 98 [2] 4e 89 [2] 00 85 [2] 0c 8f [2] 1b 84 [2] 00 ca [2] 3d }

  condition:
    any of them
}