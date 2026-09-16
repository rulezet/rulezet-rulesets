rule TTP_XOR_MULT_DOSStub_3253 {
  strings:
    $key_3253 = { 66 3b [2] 12 23 [2] 55 21 [2] 12 30 [2] 5c 3c [2] 50 36 [2] 47 3d [2] 5c 73 [2] 61 }

  condition:
    any of them
}