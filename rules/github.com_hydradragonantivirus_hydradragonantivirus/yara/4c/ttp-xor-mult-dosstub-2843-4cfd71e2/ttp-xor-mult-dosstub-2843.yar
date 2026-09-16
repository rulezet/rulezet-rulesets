rule TTP_XOR_MULT_DOSStub_2843 {
  strings:
    $key_2843 = { 7c 2b [2] 08 33 [2] 4f 31 [2] 08 20 [2] 46 2c [2] 4a 26 [2] 5d 2d [2] 46 63 [2] 7b }

  condition:
    any of them
}