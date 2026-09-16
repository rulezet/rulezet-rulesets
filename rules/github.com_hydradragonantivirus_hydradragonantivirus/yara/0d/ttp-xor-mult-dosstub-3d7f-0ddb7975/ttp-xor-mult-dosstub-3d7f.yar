rule TTP_XOR_MULT_DOSStub_3d7f {
  strings:
    $key_3d7f = { 69 17 [2] 1d 0f [2] 5a 0d [2] 1d 1c [2] 53 10 [2] 5f 1a [2] 48 11 [2] 53 5f [2] 6e }

  condition:
    any of them
}