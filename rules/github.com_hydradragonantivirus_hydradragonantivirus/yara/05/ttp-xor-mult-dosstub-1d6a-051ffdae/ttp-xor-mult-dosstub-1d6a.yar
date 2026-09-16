rule TTP_XOR_MULT_DOSStub_1d6a {
  strings:
    $key_1d6a = { 49 02 [2] 3d 1a [2] 7a 18 [2] 3d 09 [2] 73 05 [2] 7f 0f [2] 68 04 [2] 73 4a [2] 4e }

  condition:
    any of them
}