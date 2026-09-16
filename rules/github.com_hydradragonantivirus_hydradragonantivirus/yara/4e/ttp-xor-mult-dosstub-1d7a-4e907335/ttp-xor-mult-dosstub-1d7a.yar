rule TTP_XOR_MULT_DOSStub_1d7a {
  strings:
    $key_1d7a = { 49 12 [2] 3d 0a [2] 7a 08 [2] 3d 19 [2] 73 15 [2] 7f 1f [2] 68 14 [2] 73 5a [2] 4e }

  condition:
    any of them
}