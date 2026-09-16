rule TTP_XOR_MULT_DOSStub_5753 {
  strings:
    $key_5753 = { 03 3b [2] 77 23 [2] 30 21 [2] 77 30 [2] 39 3c [2] 35 36 [2] 22 3d [2] 39 73 [2] 04 }

  condition:
    any of them
}