rule TTP_XOR_MULT_DOSStub_e07c {
  strings:
    $key_e07c = { b4 14 [2] c0 0c [2] 87 0e [2] c0 1f [2] 8e 13 [2] 82 19 [2] 95 12 [2] 8e 5c [2] b3 }

  condition:
    any of them
}