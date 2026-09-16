rule TTP_XOR_MULT_DOSStub_6dea {
  strings:
    $key_6dea = { 39 82 [2] 4d 9a [2] 0a 98 [2] 4d 89 [2] 03 85 [2] 0f 8f [2] 18 84 [2] 03 ca [2] 3e }

  condition:
    any of them
}