rule TTP_XOR_MULT_DOSStub_825b {
  strings:
    $key_825b = { d6 33 [2] a2 2b [2] e5 29 [2] a2 38 [2] ec 34 [2] e0 3e [2] f7 35 [2] ec 7b [2] d1 }

  condition:
    any of them
}