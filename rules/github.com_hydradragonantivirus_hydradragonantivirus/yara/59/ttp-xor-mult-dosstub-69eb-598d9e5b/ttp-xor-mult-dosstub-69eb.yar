rule TTP_XOR_MULT_DOSStub_69eb {
  strings:
    $key_69eb = { 3d 83 [2] 49 9b [2] 0e 99 [2] 49 88 [2] 07 84 [2] 0b 8e [2] 1c 85 [2] 07 cb [2] 3a }

  condition:
    any of them
}