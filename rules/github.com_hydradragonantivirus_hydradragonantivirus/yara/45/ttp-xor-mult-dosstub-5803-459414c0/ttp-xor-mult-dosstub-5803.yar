rule TTP_XOR_MULT_DOSStub_5803 {
  strings:
    $key_5803 = { 0c 6b [2] 78 73 [2] 3f 71 [2] 78 60 [2] 36 6c [2] 3a 66 [2] 2d 6d [2] 36 23 [2] 0b }

  condition:
    any of them
}