rule TTP_XOR_MULT_DOSStub_0eaa {
  strings:
    $key_0eaa = { 5a c2 [2] 2e da [2] 69 d8 [2] 2e c9 [2] 60 c5 [2] 6c cf [2] 7b c4 [2] 60 8a [2] 5d }

  condition:
    any of them
}