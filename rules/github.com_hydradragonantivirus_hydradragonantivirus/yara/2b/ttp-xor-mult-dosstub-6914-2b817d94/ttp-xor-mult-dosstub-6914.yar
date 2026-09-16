rule TTP_XOR_MULT_DOSStub_6914 {
  strings:
    $key_6914 = { 3d 7c [2] 49 64 [2] 0e 66 [2] 49 77 [2] 07 7b [2] 0b 71 [2] 1c 7a [2] 07 34 [2] 3a }

  condition:
    any of them
}