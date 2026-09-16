rule TTP_XOR_MULT_DOSStub_8fae {
  strings:
    $key_8fae = { db c6 [2] af de [2] e8 dc [2] af cd [2] e1 c1 [2] ed cb [2] fa c0 [2] e1 8e [2] dc }

  condition:
    any of them
}