rule TTP_XOR_MULT_DOSStub_6e0f {
  strings:
    $key_6e0f = { 3a 67 [2] 4e 7f [2] 09 7d [2] 4e 6c [2] 00 60 [2] 0c 6a [2] 1b 61 [2] 00 2f [2] 3d }

  condition:
    any of them
}