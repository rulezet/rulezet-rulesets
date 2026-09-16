rule TTP_XOR_MULT_DOSStub_8fbf {
  strings:
    $key_8fbf = { db d7 [2] af cf [2] e8 cd [2] af dc [2] e1 d0 [2] ed da [2] fa d1 [2] e1 9f [2] dc }

  condition:
    any of them
}