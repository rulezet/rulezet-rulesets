rule TTP_XOR_MULT_DOSStub_0dea {
  strings:
    $key_0dea = { 59 82 [2] 2d 9a [2] 6a 98 [2] 2d 89 [2] 63 85 [2] 6f 8f [2] 78 84 [2] 63 ca [2] 5e }

  condition:
    any of them
}