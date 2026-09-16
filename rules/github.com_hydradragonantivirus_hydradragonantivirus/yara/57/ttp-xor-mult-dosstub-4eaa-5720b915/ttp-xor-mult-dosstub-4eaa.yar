rule TTP_XOR_MULT_DOSStub_4eaa {
  strings:
    $key_4eaa = { 1a c2 [2] 6e da [2] 29 d8 [2] 6e c9 [2] 20 c5 [2] 2c cf [2] 3b c4 [2] 20 8a [2] 1d }

  condition:
    any of them
}