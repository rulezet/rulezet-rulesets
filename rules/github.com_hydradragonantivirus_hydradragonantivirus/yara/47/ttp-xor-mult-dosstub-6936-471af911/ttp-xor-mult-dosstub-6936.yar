rule TTP_XOR_MULT_DOSStub_6936 {
  strings:
    $key_6936 = { 3d 5e [2] 49 46 [2] 0e 44 [2] 49 55 [2] 07 59 [2] 0b 53 [2] 1c 58 [2] 07 16 [2] 3a }

  condition:
    any of them
}