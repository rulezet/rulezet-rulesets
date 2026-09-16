rule TTP_XOR_MULT_DOSStub_ceac {
  strings:
    $key_ceac = { 9a c4 [2] ee dc [2] a9 de [2] ee cf [2] a0 c3 [2] ac c9 [2] bb c2 [2] a0 8c [2] 9d }

  condition:
    any of them
}