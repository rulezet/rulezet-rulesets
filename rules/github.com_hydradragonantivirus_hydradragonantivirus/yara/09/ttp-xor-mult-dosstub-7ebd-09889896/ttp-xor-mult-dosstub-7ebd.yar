rule TTP_XOR_MULT_DOSStub_7ebd {
  strings:
    $key_7ebd = { 2a d5 [2] 5e cd [2] 19 cf [2] 5e de [2] 10 d2 [2] 1c d8 [2] 0b d3 [2] 10 9d [2] 2d }

  condition:
    any of them
}