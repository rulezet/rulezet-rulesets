rule TTP_XOR_MULT_DOSStub_8fbd {
  strings:
    $key_8fbd = { db d5 [2] af cd [2] e8 cf [2] af de [2] e1 d2 [2] ed d8 [2] fa d3 [2] e1 9d [2] dc }

  condition:
    any of them
}