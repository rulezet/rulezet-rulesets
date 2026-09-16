rule TTP_XOR_MULT_DOSStub_4862 {
  strings:
    $key_4862 = { 1c 0a [2] 68 12 [2] 2f 10 [2] 68 01 [2] 26 0d [2] 2a 07 [2] 3d 0c [2] 26 42 [2] 1b }

  condition:
    any of them
}