rule TTP_XOR_MULT_DOSStub_0423 {
  strings:
    $key_0423 = { 50 4b [2] 24 53 [2] 63 51 [2] 24 40 [2] 6a 4c [2] 66 46 [2] 71 4d [2] 6a 03 [2] 57 }

  condition:
    any of them
}