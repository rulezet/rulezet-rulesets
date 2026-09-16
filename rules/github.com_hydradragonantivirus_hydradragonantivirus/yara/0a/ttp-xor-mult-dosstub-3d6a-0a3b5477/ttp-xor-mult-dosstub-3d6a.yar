rule TTP_XOR_MULT_DOSStub_3d6a {
  strings:
    $key_3d6a = { 69 02 [2] 1d 1a [2] 5a 18 [2] 1d 09 [2] 53 05 [2] 5f 0f [2] 48 04 [2] 53 4a [2] 6e }

  condition:
    any of them
}