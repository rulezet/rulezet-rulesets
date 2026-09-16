rule TTP_XOR_MULT_DOSStub_1ebd {
  strings:
    $key_1ebd = { 4a d5 [2] 3e cd [2] 79 cf [2] 3e de [2] 70 d2 [2] 7c d8 [2] 6b d3 [2] 70 9d [2] 4d }

  condition:
    any of them
}