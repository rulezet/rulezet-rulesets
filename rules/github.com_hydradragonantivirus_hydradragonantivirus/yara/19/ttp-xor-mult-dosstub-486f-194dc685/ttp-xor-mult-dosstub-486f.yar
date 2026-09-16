rule TTP_XOR_MULT_DOSStub_486f {
  strings:
    $key_486f = { 1c 07 [2] 68 1f [2] 2f 1d [2] 68 0c [2] 26 00 [2] 2a 0a [2] 3d 01 [2] 26 4f [2] 1b }

  condition:
    any of them
}