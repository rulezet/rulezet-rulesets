rule TTP_XOR_MULT_DOSStub_691b {
  strings:
    $key_691b = { 3d 73 [2] 49 6b [2] 0e 69 [2] 49 78 [2] 07 74 [2] 0b 7e [2] 1c 75 [2] 07 3b [2] 3a }

  condition:
    any of them
}