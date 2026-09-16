rule TTP_XOR_MULT_DOSStub_a43a {
  strings:
    $key_a43a = { f0 52 [2] 84 4a [2] c3 48 [2] 84 59 [2] ca 55 [2] c6 5f [2] d1 54 [2] ca 1a [2] f7 }

  condition:
    any of them
}