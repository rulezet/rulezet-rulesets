rule TTP_XOR_MULT_DOSStub_e73c {
  strings:
    $key_e73c = { b3 54 [2] c7 4c [2] 80 4e [2] c7 5f [2] 89 53 [2] 85 59 [2] 92 52 [2] 89 1c [2] b4 }

  condition:
    any of them
}