rule TTP_XOR_MULT_DOSStub_1f6a {
  strings:
    $key_1f6a = { 4b 02 [2] 3f 1a [2] 78 18 [2] 3f 09 [2] 71 05 [2] 7d 0f [2] 6a 04 [2] 71 4a [2] 4c }

  condition:
    any of them
}