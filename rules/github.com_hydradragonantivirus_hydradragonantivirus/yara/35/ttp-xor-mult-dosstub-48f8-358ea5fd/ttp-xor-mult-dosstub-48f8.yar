rule TTP_XOR_MULT_DOSStub_48f8 {
  strings:
    $key_48f8 = { 1c 90 [2] 68 88 [2] 2f 8a [2] 68 9b [2] 26 97 [2] 2a 9d [2] 3d 96 [2] 26 d8 [2] 1b }

  condition:
    any of them
}