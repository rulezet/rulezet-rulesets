rule TTP_XOR_MULT_DOSStub_6366 {
  strings:
    $key_6366 = { 37 0e [2] 43 16 [2] 04 14 [2] 43 05 [2] 0d 09 [2] 01 03 [2] 16 08 [2] 0d 46 [2] 30 }

  condition:
    any of them
}