rule TTP_XOR_MULT_DOSStub_48eb {
  strings:
    $key_48eb = { 1c 83 [2] 68 9b [2] 2f 99 [2] 68 88 [2] 26 84 [2] 2a 8e [2] 3d 85 [2] 26 cb [2] 1b }

  condition:
    any of them
}