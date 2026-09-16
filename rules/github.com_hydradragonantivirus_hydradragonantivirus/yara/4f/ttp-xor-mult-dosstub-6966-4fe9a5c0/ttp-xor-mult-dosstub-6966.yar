rule TTP_XOR_MULT_DOSStub_6966 {
  strings:
    $key_6966 = { 3d 0e [2] 49 16 [2] 0e 14 [2] 49 05 [2] 07 09 [2] 0b 03 [2] 1c 08 [2] 07 46 [2] 3a }

  condition:
    any of them
}