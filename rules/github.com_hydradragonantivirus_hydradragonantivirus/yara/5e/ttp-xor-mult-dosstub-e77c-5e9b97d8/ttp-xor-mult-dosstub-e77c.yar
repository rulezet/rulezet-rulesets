rule TTP_XOR_MULT_DOSStub_e77c {
  strings:
    $key_e77c = { b3 14 [2] c7 0c [2] 80 0e [2] c7 1f [2] 89 13 [2] 85 19 [2] 92 12 [2] 89 5c [2] b4 }

  condition:
    any of them
}