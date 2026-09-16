rule TTP_XOR_MULT_DOSStub_bebd {
  strings:
    $key_bebd = { ea d5 [2] 9e cd [2] d9 cf [2] 9e de [2] d0 d2 [2] dc d8 [2] cb d3 [2] d0 9d [2] ed }

  condition:
    any of them
}