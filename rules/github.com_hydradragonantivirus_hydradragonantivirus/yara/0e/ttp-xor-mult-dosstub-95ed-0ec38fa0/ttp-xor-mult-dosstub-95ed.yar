rule TTP_XOR_MULT_DOSStub_95ed {
  strings:
    $key_95ed = { c1 85 [2] b5 9d [2] f2 9f [2] b5 8e [2] fb 82 [2] f7 88 [2] e0 83 [2] fb cd [2] c6 }

  condition:
    any of them
}