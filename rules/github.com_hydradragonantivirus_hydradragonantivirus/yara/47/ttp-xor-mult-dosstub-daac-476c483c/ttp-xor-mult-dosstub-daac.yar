rule TTP_XOR_MULT_DOSStub_daac {
  strings:
    $key_daac = { 8e c4 [2] fa dc [2] bd de [2] fa cf [2] b4 c3 [2] b8 c9 [2] af c2 [2] b4 8c [2] 89 }

  condition:
    any of them
}