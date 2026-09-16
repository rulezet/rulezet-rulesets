rule TTP_XOR_MULT_DOSStub_5a23 {
  strings:
    $key_5a23 = { 0e 4b [2] 7a 53 [2] 3d 51 [2] 7a 40 [2] 34 4c [2] 38 46 [2] 2f 4d [2] 34 03 [2] 09 }

  condition:
    any of them
}