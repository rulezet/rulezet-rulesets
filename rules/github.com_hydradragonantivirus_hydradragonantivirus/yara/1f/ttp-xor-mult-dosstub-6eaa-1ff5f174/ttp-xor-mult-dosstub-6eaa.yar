rule TTP_XOR_MULT_DOSStub_6eaa {
  strings:
    $key_6eaa = { 3a c2 [2] 4e da [2] 09 d8 [2] 4e c9 [2] 00 c5 [2] 0c cf [2] 1b c4 [2] 00 8a [2] 3d }

  condition:
    any of them
}