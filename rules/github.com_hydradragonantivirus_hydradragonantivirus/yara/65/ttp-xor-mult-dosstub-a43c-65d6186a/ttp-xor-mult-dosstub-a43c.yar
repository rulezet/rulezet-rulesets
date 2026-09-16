rule TTP_XOR_MULT_DOSStub_a43c {
  strings:
    $key_a43c = { f0 54 [2] 84 4c [2] c3 4e [2] 84 5f [2] ca 53 [2] c6 59 [2] d1 52 [2] ca 1c [2] f7 }

  condition:
    any of them
}