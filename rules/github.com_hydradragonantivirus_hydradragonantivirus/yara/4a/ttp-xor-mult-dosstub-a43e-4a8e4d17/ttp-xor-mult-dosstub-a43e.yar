rule TTP_XOR_MULT_DOSStub_a43e {
  strings:
    $key_a43e = { f0 56 [2] 84 4e [2] c3 4c [2] 84 5d [2] ca 51 [2] c6 5b [2] d1 50 [2] ca 1e [2] f7 }

  condition:
    any of them
}