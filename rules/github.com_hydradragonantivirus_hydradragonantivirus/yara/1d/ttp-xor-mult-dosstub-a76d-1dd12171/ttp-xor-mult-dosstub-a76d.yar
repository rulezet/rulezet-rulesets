rule TTP_XOR_MULT_DOSStub_a76d {
  strings:
    $key_a76d = { f3 05 [2] 87 1d [2] c0 1f [2] 87 0e [2] c9 02 [2] c5 08 [2] d2 03 [2] c9 4d [2] f4 }

  condition:
    any of them
}