rule TTP_XOR_MULT_DOSStub_69fc {
  strings:
    $key_69fc = { 3d 94 [2] 49 8c [2] 0e 8e [2] 49 9f [2] 07 93 [2] 0b 99 [2] 1c 92 [2] 07 dc [2] 3a }

  condition:
    any of them
}