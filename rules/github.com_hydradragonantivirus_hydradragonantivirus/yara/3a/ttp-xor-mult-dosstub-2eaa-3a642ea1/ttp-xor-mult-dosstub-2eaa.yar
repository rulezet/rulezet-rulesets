rule TTP_XOR_MULT_DOSStub_2eaa {
  strings:
    $key_2eaa = { 7a c2 [2] 0e da [2] 49 d8 [2] 0e c9 [2] 40 c5 [2] 4c cf [2] 5b c4 [2] 40 8a [2] 7d }

  condition:
    any of them
}