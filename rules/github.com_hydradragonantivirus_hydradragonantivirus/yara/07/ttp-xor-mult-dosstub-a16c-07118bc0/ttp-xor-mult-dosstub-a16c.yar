rule TTP_XOR_MULT_DOSStub_a16c {
  strings:
    $key_a16c = { f5 04 [2] 81 1c [2] c6 1e [2] 81 0f [2] cf 03 [2] c3 09 [2] d4 02 [2] cf 4c [2] f2 }

  condition:
    any of them
}