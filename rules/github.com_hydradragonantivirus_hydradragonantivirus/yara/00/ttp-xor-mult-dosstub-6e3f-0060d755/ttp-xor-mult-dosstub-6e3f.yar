rule TTP_XOR_MULT_DOSStub_6e3f {
  strings:
    $key_6e3f = { 3a 57 [2] 4e 4f [2] 09 4d [2] 4e 5c [2] 00 50 [2] 0c 5a [2] 1b 51 [2] 00 1f [2] 3d }

  condition:
    any of them
}