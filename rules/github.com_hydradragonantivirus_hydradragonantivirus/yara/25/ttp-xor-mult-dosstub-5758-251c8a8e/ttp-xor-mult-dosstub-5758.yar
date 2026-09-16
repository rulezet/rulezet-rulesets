rule TTP_XOR_MULT_DOSStub_5758 {
  strings:
    $key_5758 = { 03 30 [2] 77 28 [2] 30 2a [2] 77 3b [2] 39 37 [2] 35 3d [2] 22 36 [2] 39 78 [2] 04 }

  condition:
    any of them
}