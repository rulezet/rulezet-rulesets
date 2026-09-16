rule TTP_XOR_MULT_DOSStub_1dea {
  strings:
    $key_1dea = { 49 82 [2] 3d 9a [2] 7a 98 [2] 3d 89 [2] 73 85 [2] 7f 8f [2] 68 84 [2] 73 ca [2] 4e }

  condition:
    any of them
}