rule TTP_XOR_MULT_DOSStub_e366 {
  strings:
    $key_e366 = { b7 0e [2] c3 16 [2] 84 14 [2] c3 05 [2] 8d 09 [2] 81 03 [2] 96 08 [2] 8d 46 [2] b0 }

  condition:
    any of them
}