rule TTP_XOR_MULT_DOSStub_6926 {
  strings:
    $key_6926 = { 3d 4e [2] 49 56 [2] 0e 54 [2] 49 45 [2] 07 49 [2] 0b 43 [2] 1c 48 [2] 07 06 [2] 3a }

  condition:
    any of them
}