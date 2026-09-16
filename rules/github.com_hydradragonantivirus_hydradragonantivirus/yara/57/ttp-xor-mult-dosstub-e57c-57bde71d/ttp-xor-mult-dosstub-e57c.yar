rule TTP_XOR_MULT_DOSStub_e57c {
  strings:
    $key_e57c = { b1 14 [2] c5 0c [2] 82 0e [2] c5 1f [2] 8b 13 [2] 87 19 [2] 90 12 [2] 8b 5c [2] b6 }

  condition:
    any of them
}