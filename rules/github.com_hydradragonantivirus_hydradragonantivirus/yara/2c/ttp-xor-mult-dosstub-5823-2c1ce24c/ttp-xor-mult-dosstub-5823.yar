rule TTP_XOR_MULT_DOSStub_5823 {
  strings:
    $key_5823 = { 0c 4b [2] 78 53 [2] 3f 51 [2] 78 40 [2] 36 4c [2] 3a 46 [2] 2d 4d [2] 36 03 [2] 0b }

  condition:
    any of them
}