rule TTP_XOR_MULT_DOSStub_1eaa {
  strings:
    $key_1eaa = { 4a c2 [2] 3e da [2] 79 d8 [2] 3e c9 [2] 70 c5 [2] 7c cf [2] 6b c4 [2] 70 8a [2] 4d }

  condition:
    any of them
}