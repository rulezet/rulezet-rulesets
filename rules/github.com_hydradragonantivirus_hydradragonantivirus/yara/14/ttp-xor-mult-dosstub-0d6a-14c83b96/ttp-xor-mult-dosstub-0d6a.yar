rule TTP_XOR_MULT_DOSStub_0d6a {
  strings:
    $key_0d6a = { 59 02 [2] 2d 1a [2] 6a 18 [2] 2d 09 [2] 63 05 [2] 6f 0f [2] 78 04 [2] 63 4a [2] 5e }

  condition:
    any of them
}