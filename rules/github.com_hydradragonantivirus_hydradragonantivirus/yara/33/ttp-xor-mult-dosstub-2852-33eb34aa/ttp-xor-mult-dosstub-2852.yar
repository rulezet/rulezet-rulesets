rule TTP_XOR_MULT_DOSStub_2852 {
  strings:
    $key_2852 = { 7c 3a [2] 08 22 [2] 4f 20 [2] 08 31 [2] 46 3d [2] 4a 37 [2] 5d 3c [2] 46 72 [2] 7b }

  condition:
    any of them
}