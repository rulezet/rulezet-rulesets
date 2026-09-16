rule TTP_XOR_MULT_DOSStub_3d6f {
  strings:
    $key_3d6f = { 69 07 [2] 1d 1f [2] 5a 1d [2] 1d 0c [2] 53 00 [2] 5f 0a [2] 48 01 [2] 53 4f [2] 6e }

  condition:
    any of them
}