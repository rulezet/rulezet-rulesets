rule TTP_XOR_MULT_DOSStub_5eaa {
  strings:
    $key_5eaa = { 0a c2 [2] 7e da [2] 39 d8 [2] 7e c9 [2] 30 c5 [2] 3c cf [2] 2b c4 [2] 30 8a [2] 0d }

  condition:
    any of them
}