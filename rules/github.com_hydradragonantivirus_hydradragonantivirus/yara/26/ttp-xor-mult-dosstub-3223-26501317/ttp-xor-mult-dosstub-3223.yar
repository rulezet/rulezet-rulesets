rule TTP_XOR_MULT_DOSStub_3223 {
  strings:
    $key_3223 = { 66 4b [2] 12 53 [2] 55 51 [2] 12 40 [2] 5c 4c [2] 50 46 [2] 47 4d [2] 5c 03 [2] 61 }

  condition:
    any of them
}