rule TTP_XOR_MULT_DOSStub_4809 {
  strings:
    $key_4809 = { 1c 61 [2] 68 79 [2] 2f 7b [2] 68 6a [2] 26 66 [2] 2a 6c [2] 3d 67 [2] 26 29 [2] 1b }

  condition:
    any of them
}