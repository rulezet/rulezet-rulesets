rule TTP_XOR_MULT_DOSStub_6e7f {
  strings:
    $key_6e7f = { 3a 17 [2] 4e 0f [2] 09 0d [2] 4e 1c [2] 00 10 [2] 0c 1a [2] 1b 11 [2] 00 5f [2] 3d }

  condition:
    any of them
}