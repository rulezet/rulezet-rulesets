rule TTP_XOR_MULT_DOSStub_48f5 {
  strings:
    $key_48f5 = { 1c 9d [2] 68 85 [2] 2f 87 [2] 68 96 [2] 26 9a [2] 2a 90 [2] 3d 9b [2] 26 d5 [2] 1b }

  condition:
    any of them
}